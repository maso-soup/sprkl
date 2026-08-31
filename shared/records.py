"""Transcript format v1 — shared reference.

Imported by the proxy, the app's tap, and the scorer, so the three cannot drift.
Constructors are the ONLY sanctioned way to produce a record; `validate` is what
the scorer applies to every line before it reaches a rule.

Nothing here interprets. If you find yourself adding a field that names a
finding, a severity, or a verdict, it belongs in the scorer's ruleset instead.
"""
import base64, hashlib, json, os, time

V = 1

# Response bodies are capped; request bodies are always retained in full via the
# blob store, because for zip-slip / pickle / XXE-SVG / webshell uploads the
# uploaded bytes ARE the evidence and a crafted payload will exceed any cap.
RES_BODY_CAP = 64 * 1024
INLINE_CAP = 16 * 1024
# Response payloads no rule will read. Note image/svg+xml is deliberately NOT
# covered by the image/ prefix check below: SVG is text and carries XXE.
SKIP_RES_CTYPES = ("image/", "font/", "video/", "audio/")

TAP_KINDS = frozenset({
    "auth.result", "sql.exec", "nosql.find", "ldap.search", "xpath.eval",
    "fs.read", "tmpl.render", "code.eval", "deser.load", "proc.exec",
    "archive.extract", "net.fetch", "xml.parse", "mail.send", "cache.store",
    "coupon.redeem", "order.total", "order.finalize", "giftcard.redeem",
    "token.issue", "obj.assign", "ws.message",
})
TYPES = frozenset({"manifest", "run", "ingress", "tap", "egress", "oast"})

# Producers observed outside the app process. A rule reading only these cannot
# be fooled by an app the tester has fully compromised.
TRUSTED_TYPES = frozenset({"ingress", "oast"})

REQUEST_ID_HEADER = "X-Request-Id"


class BlobStore:
    """Content-addressed store for bodies too large to inline."""

    def __init__(self, root):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def put(self, data):
        digest = hashlib.sha256(data).hexdigest()
        path = os.path.join(self.root, digest)
        if not os.path.exists(path):
            tmp = path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, path)
        return digest

    def get(self, digest):
        with open(os.path.join(self.root, digest), "rb") as fh:
            return fh.read()


def _ctype(headers):
    return next((v for k, v in headers if k.lower() == "content-type"), None)


def _req_body(data, blobs):
    """Request bodies are retained in full: small ones inline, large ones by blob."""
    if not data:
        return {"body_b64": None, "body_len": 0, "body_sha256": None,
                "body_truncated": False, "body_blob": None}
    digest = hashlib.sha256(data).hexdigest()
    blob = blobs.put(data) if blobs is not None else None
    inline = base64.b64encode(data).decode() if len(data) <= INLINE_CAP else None
    return {"body_b64": inline, "body_len": len(data), "body_sha256": digest,
            "body_truncated": inline is None, "body_blob": blob}


def _res_body(data, ctype):
    if not data:
        return {"body_b64": None, "body_len": 0, "body_sha256": None,
                "body_truncated": False}
    digest = hashlib.sha256(data).hexdigest()
    base = ctype.split(";")[0].strip().lower() if ctype else ""
    if base.startswith(SKIP_RES_CTYPES):
        return {"body_b64": None, "body_len": len(data), "body_sha256": digest,
                "body_truncated": True}
    return {"body_b64": base64.b64encode(data[:RES_BODY_CAP]).decode(),
            "body_len": len(data), "body_sha256": digest,
            "body_truncated": len(data) > RES_BODY_CAP}


# --- constructors ----------------------------------------------------------

def manifest(run, app, seed, canaries, accounts, secrets,
             internal_cidrs, canary_prefix):
    return {"v": V, "t": "manifest", "ts": time.time(), "run": run, "app": app,
            "seed": seed, "canaries": canaries, "accounts": accounts,
            "secrets": secrets, "internal_cidrs": internal_cidrs,
            "canary_prefix": canary_prefix}


def run_marker(phase, note=None):
    assert phase in ("start", "seeded", "end")
    return {"v": V, "t": "run", "ts": time.time(), "phase": phase, "note": note}


def ingress(rid, conn, req_line, method, target, path, query, req_headers,
            req_body, status, reason, res_headers, res_body,
            ttfb_ms, total_ms, identity, blobs=None, ts=None):
    return {
        "v": V, "t": "ingress", "ts": ts if ts is not None else time.time(),
        "rid": rid, "conn": conn,
        "req": {"line": req_line, "method": method, "target": target,
                "path": path, "query": query,
                "headers": [list(h) for h in req_headers],
                **_req_body(req_body, blobs)},
        "res": {"status": status, "reason": reason,
                "headers": [list(h) for h in res_headers],
                **_res_body(res_body, _ctype(res_headers))},
        "timing": {"ttfb_ms": ttfb_ms, "total_ms": total_ms},
        "identity": identity,
    }


def tap(rid, seq, kind, /, **d):
    # `kind` is positional-only so a payload field may itself be named `kind`.
    assert kind in TAP_KINDS, f"unknown tap kind: {kind}"
    return {"v": V, "t": "tap", "ts": time.time(), "rid": rid, "seq": seq,
            "k": kind, "d": d}


def egress(rid, obs, dst, req, res, connected):
    assert obs in ("network", "app")
    return {"v": V, "t": "egress", "ts": time.time(), "rid": rid, "obs": obs,
            "dst": dst, "req": req, "res": res, "connected": connected}


def oast(token, src_ip, method, path, ua):
    return {"v": V, "t": "oast", "ts": time.time(), "token": token,
            "src_ip": src_ip, "method": method, "path": path, "ua": ua}


# --- validation ------------------------------------------------------------

class BadRecord(ValueError):
    pass


def validate(rec):
    if not isinstance(rec, dict):
        raise BadRecord("not an object")
    if rec.get("v") != V:
        raise BadRecord(f"unsupported version {rec.get('v')!r}")
    t = rec.get("t")
    if t not in TYPES:
        raise BadRecord(f"unknown type {t!r}")
    if not isinstance(rec.get("ts"), (int, float)):
        raise BadRecord("missing ts")
    if t == "tap" and rec.get("k") not in TAP_KINDS:
        raise BadRecord(f"unknown tap kind {rec.get('k')!r}")
    if t in ("ingress", "tap") and "rid" not in rec:
        raise BadRecord("missing rid")
    return rec


def trusted(rec):
    """True if this record was observed outside the app process."""
    return rec["t"] in TRUSTED_TYPES or (
        rec["t"] == "egress" and rec.get("obs") == "network")


# --- join / seal -----------------------------------------------------------

class Sealer:
    """Groups tap/egress records onto their ingress and releases sealed bundles.

    Late evidence re-releases an already-sealed bundle; the scorer re-evaluates,
    which is safe because solving is idempotent per (finding, actor).

    A tap whose rid never receives an ingress is quarantined and never scored.
    That is the anti-forgery property: an app the tester controls can write
    events, but it cannot manufacture a proxy observation to hang them on.
    """

    def __init__(self, grace=0.5, quarantine_after=30.0):
        self.grace = grace
        self.quarantine_after = quarantine_after
        self.bundles = {}
        self.quarantined = 0

    def add(self, rec):
        validate(rec)
        if rec["t"] in ("manifest", "run", "oast"):
            return [("standalone", rec)]
        rid = rec.get("rid")
        if rid is None:
            return [("unbound", rec)]
        b = self.bundles.setdefault(
            rid, {"rid": rid, "ingress": None, "events": [],
                  "sealed": False, "first": rec["ts"]})
        if rec["t"] == "ingress":
            b["ingress"] = rec
        else:
            b["events"].append(rec)
        if b["sealed"] and b["ingress"] is not None:
            return [("reseal", b)]
        return []

    def tick(self, now=None):
        now = now or time.time()
        out = []
        for rid, b in list(self.bundles.items()):
            ing = b["ingress"]
            if ing is None:
                if now - b["first"] > self.quarantine_after:
                    del self.bundles[rid]
                    self.quarantined += 1
                continue
            done_at = ing["ts"] + (ing["timing"]["total_ms"] / 1000.0) + self.grace
            if not b["sealed"] and now >= done_at:
                b["sealed"] = True
                out.append(("seal", b))
        return out

    def drain(self):
        """Seal everything outstanding — end of run, or replay of a finished file."""
        out = []
        for b in self.bundles.values():
            if b["ingress"] is not None and not b["sealed"]:
                b["sealed"] = True
                out.append(("seal", b))
        return out


def loads(line):
    return validate(json.loads(line))


def dumps(rec):
    return json.dumps(rec, separators=(",", ":"), default=str)
