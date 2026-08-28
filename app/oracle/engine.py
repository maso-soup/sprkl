"""The oracle: server-side ground truth for exploited findings.

`solve()` is the ONLY way a finding is marked discovered. It is called exclusively
from vulnerable code paths, gated on a predicate that is true only when the vuln is
genuinely exploited. There is no client-reachable "mark solved" endpoint.
"""
import json, time
from .. import db
from . import catalog

# In-memory registry of planted canary secrets: token -> (owner, kind).
# Populated by seed.py; used to prove a secret actually leaked to an
# unauthorized actor (the `canary` oracle strategy).
CANARIES = {}


def register_canary(token, owner, kind):
    CANARIES[token] = {"owner": owner, "kind": kind}


def solve(finding_id, actor, evidence=None):
    """Record a genuine exploitation. Idempotent per (finding, actor)."""
    f = catalog.by_id(finding_id)
    if not f or f.get("status") != "live":
        return False
    try:
        db.execute(
            "INSERT OR IGNORE INTO solves (finding_id, actor, evidence, ts) "
            "VALUES (?,?,?,?)",
            (finding_id, actor or "anonymous",
             json.dumps(evidence or {}, default=str)[:4000], time.time()),
        )
    except Exception:
        return False
    return True


def solved_ids():
    rows = db.query("SELECT DISTINCT finding_id FROM solves")
    return {r["finding_id"] for r in rows}


# ---- canary helpers -------------------------------------------------------

def find_canary(text):
    """Return the first planted canary token that appears in `text`, else None."""
    if not text:
        return None
    s = text if isinstance(text, str) else str(text)
    for token in CANARIES:
        if token in s:
            return token
    return None


def leaked_canary(finding_id, actor, text, owner_ok=None):
    """Solve `finding_id` if ANY planted canary that the actor does not own appears
    in `text`. Scans every canary (not just the first) so leaking other users'
    secrets still fires even when the actor's own secret is also present."""
    if not text:
        return False
    s = text if isinstance(text, str) else str(text)
    for token, meta in CANARIES.items():
        if token not in s:
            continue
        if owner_ok is not None and actor == owner_ok:
            continue
        if actor is not None and actor == meta.get("owner"):
            continue
        return solve(finding_id, actor,
                     {"canary": token, "kind": meta.get("kind"),
                      "owner": meta.get("owner")})
    return False
