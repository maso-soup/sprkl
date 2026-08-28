"""OAST / out-of-band collector for blind findings.

Blind findings (blind command injection, blind SSRF, blind XSS, host-header,
OAuth redirect, etc.) can only be proven by an out-of-band callback. Flow:

  1. A vulnerable endpoint, while processing an attacker payload, scans it for a
     callback URL pointing at our collab base. If found, it `arm()`s the token,
     binding that token -> (finding_id, actor).
  2. The payload only causes a real callback to `/collab/<token>` if the vuln
     actually fired (the command ran / the server made the request / the admin's
     browser executed the script).
  3. `hit()` on that callback looks up the armed token and solves the finding.

Arming on seeing the token is intent; the *solve* only happens on the real
callback — which is the correct oracle property.
"""
import re
from .. import config
from . import engine

# token -> {"finding_id":..., "actor":...}
_armed = {}

_TOKEN_RE = re.compile(r"/collab/([A-Za-z0-9_\-\.]{3,120})")


def arm_from_payload(payload, finding_id, actor):
    """If `payload` references our collab base, arm every token found in it."""
    if not payload:
        return None
    text = payload if isinstance(payload, str) else str(payload)
    armed = None
    for tok in _TOKEN_RE.findall(text):
        _armed[tok] = {"finding_id": finding_id, "actor": actor}
        armed = tok
    return armed


def arm(token, finding_id, actor):
    _armed[token] = {"finding_id": finding_id, "actor": actor}


def hit(token, meta=None):
    """A callback arrived. Solve the armed finding, if any."""
    rec = _armed.get(token)
    if not rec:
        return None
    engine.solve(rec["finding_id"], rec["actor"],
                 {"oast_token": token, "callback": meta or {}})
    return rec["finding_id"]
