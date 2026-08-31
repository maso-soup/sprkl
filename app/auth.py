"""Authentication helpers.

The verifier honours the token's own `alg`, uses an HS256 secret drawn from a
wordlist, and resolves `kid` as a file path. Which of those paths a given token
took is reported on the tap as a plain fact about the verification.
"""
import os, json, base64, hmac, hashlib
from flask import request, session
from . import config, db, tap
from .util import actor as session_actor

STATIC_DIR = os.path.join(config.BASE_DIR, "app", "static")


def _b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def issue_jwt(uid, role):
    header = {"alg": "HS256", "typ": "JWT", "kid": "main"}
    payload = {"sub": uid, "role": role}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    sig = hmac.new(config.JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + _b64url(sig)


def verify_jwt(token):
    """Return (claims, meta) or (None, meta). meta['vuln'] flags an abused weakness."""
    meta = {"vuln": None}
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
    except Exception:
        return None, meta
    alg = (header.get("alg") or "").lower()
    signing_input = f"{h_b64}.{p_b64}"

    if alg == "none":
        meta["vuln"] = "alg-none"
        return payload, meta

    kid = header.get("kid", "main")
    if kid and kid != "main":
        key = None
        try:
            path = os.path.normpath(os.path.join(STATIC_DIR, kid))
            with open(path, "rb") as fh:
                key = fh.read()
        except Exception:
            key = None
        if key is not None:
            expect = _b64url(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())
            if hmac.compare_digest(expect, s_b64):
                meta["vuln"] = "kid-injection"
                return payload, meta

    expect = _b64url(hmac.new(config.JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest())
    if hmac.compare_digest(expect, s_b64):
        meta["vuln"] = "hs256"
        return payload, meta
    return None, meta


def api_identity():
    """Resolve the API caller: (uid, role, actor_str, jwt_meta).

    Falls back to the session user, then anonymous. jwt_meta carries which JWT
    weakness (if any) the presented token exercised; the tap reports it.
    """
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        claims, meta = verify_jwt(auth[7:])
        if claims:
            uid = claims.get("sub")
            role = claims.get("role", "customer")
            tap.emit("auth.result", mechanism="jwt", ok=True,
                     password_verified=False, principal=f"user:{uid}",
                     claimed_role=role, stored_role=db_role(uid),
                     verified_by=meta.get("vuln"))
            return uid, role, f"user:{uid}", meta
    if session.get("uid"):
        u = db.query("SELECT role FROM users WHERE id=?", (session["uid"],), one=True)
        return session["uid"], (u["role"] if u else "customer"), f"user:{session['uid']}", {"vuln": None}
    if session.get("admin"):
        cid = session["admin"]
        u = db.query("SELECT role FROM users WHERE id=?", (cid,), one=True)
        return cid, (u["role"] if u else "buyer"), f"user:{cid}", {"vuln": None}
    return None, None, session_actor(), {"vuln": None}


def db_role(uid):
    u = db.query("SELECT role FROM users WHERE id=?", (uid,), one=True)
    return u["role"] if u else None
