"""Server-side URL fetcher — the SSRF sink.

Detection is SINK-side: the server classifies the *target* it was asked to reach,
so SSRF is credited regardless of where a tester's own collaborator lives. Targets:
  - 169.254.169.254            -> cloud metadata (canary IAM creds)
  - loopback / private / *.internal / app-origin -> INTERNAL (SSRF proof)
  - our collab base            -> OAST callback (bonus path)
  - anything else (public)     -> a REAL outbound GET is attempted, so a tester can
                                  point the feature at their own listener and watch
                                  the request arrive (private ranges also really egress).
A naive literal blocklist (localhost/127.0.0.1) is applied first, so filter-bypass
variants (decimal IP, 0.0.0.0, [::], *.internal) slip past it into INTERNAL.
"""
import ipaddress, re
from urllib.parse import urlparse
from .. import config
from ..oracle import collab

# VULN: blocklist matches literal strings only.
_BLOCK = ["localhost", "127.0.0.1"]


def _is_metadata(host):
    variants = {"169.254.169.254", "0xa9fea9fe", "2852039166",
                "169.254.169.254.", "[::ffff:169.254.169.254]"}
    return host in variants or host.replace("0x", "").startswith("a9fea9fe")


def _is_internal(host):
    if not host:
        return False
    if host.endswith(".internal") or host in ("0.0.0.0", "::1", "[::1]", "0"):
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def fetch(url, finding_ctx=None):
    """Fetch `url`. Returns (status, body, meta). meta['reached'] in
    {collab, metadata, internal, blocked, external}."""
    meta = {"reached": None, "blocked": False}
    try:
        p = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return 0, "", meta
    host = (p.hostname or "").lower()

    # collab callback (OAST) — bonus proof path
    collab_host = urlparse(config.COLLAB_BASE).hostname
    if host == collab_host and "/collab/" in url:
        m = re.search(r"/collab/([A-Za-z0-9_\-\.]+)", url)
        if m and finding_ctx:
            collab.arm(m.group(1), finding_ctx[0], finding_ctx[1])
            collab.hit(m.group(1), {"via": "ssrf"})
        meta["reached"] = "collab"
        return 200, "ok", meta

    # naive literal blocklist (this is the filter that filter-bypass evades)
    if any(b == host for b in _BLOCK):
        meta["blocked"] = True
        meta["reached"] = "blocked"
        return 403, "blocked", meta

    if _is_metadata(host):
        from . import metadata
        meta["reached"] = "metadata"
        return 200, metadata.get(p.path or "/"), meta

    if _is_internal(host):
        meta["reached"] = "internal"
        _real_get(url)  # real request so a private-range listener is actually hit
        return 200, "internal-service", meta

    # public host: attempt a REAL outbound request so testers can observe it
    body = _real_get(url)
    meta["reached"] = "external"
    return 200, body or f"fetched {host}", meta


def _real_get(url):
    try:
        import requests
        r = requests.get(url if "://" in url else "http://" + url, timeout=3,
                         allow_redirects=False)
        return r.text[:500]
    except Exception:
        return ""
