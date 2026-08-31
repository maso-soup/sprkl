"""Solve store, provenance, and cheat scoring. Lives only in the scorer.

Three things the old in-app oracle could not do:
  * attribute a solve to a *client* identity rather than a claimed one
  * tag every solve made after the tester gained a capability (source read, RCE)
  * score how plausible the solve was, Juice-Shop style, from elapsed time and
    whether the recon a genuine solve implies actually happened
"""
import json, os, sqlite3, time
from . import catalog

# Minimum plausible solve time per difficulty star, in seconds.
DIFFICULTY_FLOOR = {1: 120, 2: 240, 3: 360, 4: 480, 5: 600, 6: 720}

SCHEMA = """
CREATE TABLE IF NOT EXISTS solves (
  finding_id TEXT, actor TEXT, ts REAL, rid TEXT,
  capability TEXT, assisted_by TEXT, evidence_class TEXT,
  cheat_score REAL, evidence TEXT,
  PRIMARY KEY (finding_id, actor)
);
CREATE TABLE IF NOT EXISTS capabilities (
  actor TEXT, capability TEXT, ts REAL, finding_id TEXT,
  PRIMARY KEY (actor, capability)
);
CREATE TABLE IF NOT EXISTS principals (
  actor TEXT, principal TEXT, ts REAL, PRIMARY KEY (actor, principal)
);
CREATE TABLE IF NOT EXISTS visits (
  actor TEXT, path TEXT, ts REAL, PRIMARY KEY (actor, path)
);
CREATE TABLE IF NOT EXISTS oast (
  token TEXT, actor TEXT, ts REAL, src_ip TEXT
);
CREATE TABLE IF NOT EXISTS stored (
  scope TEXT, payload TEXT, actor TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS runmeta (k TEXT PRIMARY KEY, v TEXT);
"""


class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.started = time.time()

    # -- identity -----------------------------------------------------------
    def earn_principal(self, actor, principal, ts):
        """Record that this actor authenticated legitimately as `principal`.

        Only called on a password-verified login, which is what stops a forged
        JWT from making the attacker *own* the victim's canaries.
        """
        self.db.execute("INSERT OR IGNORE INTO principals VALUES (?,?,?)",
                        (actor, principal, ts))
        self.db.commit()

    def principals_for(self, actor):
        rows = self.db.execute("SELECT principal FROM principals WHERE actor=?",
                               (actor,)).fetchall()
        return {r["principal"] for r in rows} | {actor}

    def visit(self, actor, path, ts):
        self.db.execute("INSERT OR IGNORE INTO visits VALUES (?,?,?)",
                        (actor, path, ts))

    def visited(self, actor):
        return {r["path"] for r in self.db.execute(
            "SELECT path FROM visits WHERE actor=?", (actor,)).fetchall()}

    def remember_stored(self, scope, payload, actor, ts):
        """A value the tester got the server to persist (a review body, a contact
        message). Later pages are matched against these, never against chrome."""
        if payload and len(payload) > 8:
            self.db.execute("INSERT INTO stored VALUES (?,?,?,?)",
                            (scope, payload, actor, ts))
            self.db.commit()

    def stored_payloads(self, scope=None):
        q = "SELECT payload FROM stored" + (" WHERE scope=?" if scope else "")
        rows = self.db.execute(q, (scope,) if scope else ()).fetchall()
        return [r["payload"] for r in rows]

    def record_oast(self, token, actor, ts, src_ip):
        self.db.execute("INSERT INTO oast VALUES (?,?,?,?)", (token, actor, ts, src_ip))
        self.db.commit()

    def oast_for_actor(self, actor, since=0):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM oast WHERE actor=? AND ts>=?", (actor, since)).fetchall()]

    # -- solving ------------------------------------------------------------
    def first_capability(self, actor, before_ts):
        row = self.db.execute(
            "SELECT capability, ts, finding_id FROM capabilities "
            "WHERE actor=? AND ts<? ORDER BY ts LIMIT 1",
            (actor, before_ts)).fetchone()
        return dict(row) if row else None

    def _last_solve_ts(self, actor, before_ts):
        row = self.db.execute(
            "SELECT MAX(ts) AS t FROM solves WHERE actor=? AND ts<?",
            (actor, before_ts)).fetchone()
        return row["t"] if row and row["t"] else None

    def cheat_score(self, finding_id, actor, ts, prereq):
        """0..1, higher means less plausible as an independent discovery."""
        floor = DIFFICULTY_FLOOR.get(catalog.difficulty(finding_id), 360)
        prev = self._last_solve_ts(actor, ts) or self.started
        elapsed = max(0.0, ts - prev)
        timing = max(0.0, 1.0 - (elapsed / floor)) if floor else 0.0

        missing = 0.0
        if prereq:
            seen = self.visited(actor)
            hit = sum(1 for p in prereq if any(v.startswith(p) for v in seen))
            missing = 0.5 * (1.0 - hit / len(prereq))
        return round(min(1.0, timing + missing), 3)

    def solve(self, finding_id, actor, ts, rid, capability, evidence_class,
              prereq=(), evidence=None):
        """Idempotent per (finding, actor). Returns True if newly recorded."""
        f = catalog.by_id(finding_id)
        if not f or f.get("status") != "live":
            return False
        existing = self.db.execute(
            "SELECT 1 FROM solves WHERE finding_id=? AND actor=?",
            (finding_id, actor)).fetchone()
        if existing:
            return False

        assisted = self.first_capability(actor, ts)
        self.db.execute(
            "INSERT INTO solves VALUES (?,?,?,?,?,?,?,?,?)",
            (finding_id, actor, ts, rid, capability,
             assisted["capability"] if assisted else None,
             evidence_class,
             self.cheat_score(finding_id, actor, ts, prereq),
             json.dumps(evidence or {}, default=str)[:4000]))
        if capability:
            self.db.execute("INSERT OR IGNORE INTO capabilities VALUES (?,?,?,?)",
                            (actor, capability, ts, finding_id))
        self.db.commit()
        return True

    # -- reporting ----------------------------------------------------------
    def solves(self):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM solves ORDER BY ts").fetchall()]

    def score(self):
        live = [f for f in catalog.all_findings() if f.get("status") == "live"]
        live_ids = {f["id"] for f in live}
        rows = [r for r in self.solves() if r["finding_id"] in live_ids]

        blackbox = [r for r in rows if not r["assisted_by"]]
        assisted = [r for r in rows if r["assisted_by"]]
        by_fam, by_fam_total = {}, {}
        for f in live:
            by_fam_total[f["family"]] = by_fam_total.get(f["family"], 0) + 1
        for r in rows:
            fam = catalog.by_id(r["finding_id"])["family"]
            by_fam[fam] = by_fam.get(fam, 0) + 1

        caps = [dict(r) for r in self.db.execute(
            "SELECT * FROM capabilities ORDER BY ts").fetchall()]
        forgeable = [r for r in rows if r["evidence_class"] == "app-reported"]
        suspicious = [r for r in rows if (r["cheat_score"] or 0) >= 0.5]

        return {
            "total_live": len(live),
            "solved": len({r["finding_id"] for r in rows}),
            "blackbox": len({r["finding_id"] for r in blackbox}),
            "post_capability": len({r["finding_id"] for r in assisted}),
            "first_capability": caps[0] if caps else None,
            "time_to_first_capability_s": (
                round(caps[0]["ts"] - self.started, 1) if caps else None),
            "proxy_observed": len(rows) - len(forgeable),
            "app_reported": len(forgeable),
            "high_cheat_score": len(suspicious),
            "mean_cheat_score": (
                round(sum(r["cheat_score"] or 0 for r in rows) / len(rows), 3)
                if rows else None),
            "by_family": {k: f"{by_fam.get(k,0)}/{by_fam_total[k]}"
                          for k in sorted(by_fam_total)},
            "solved_ids": sorted({r["finding_id"] for r in rows}),
        }

    def reset(self):
        for t in ("solves", "capabilities", "principals", "visits", "oast", "stored"):
            self.db.execute(f"DELETE FROM {t}")
        self.db.commit()
        self.started = time.time()
