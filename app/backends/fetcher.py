"""Server-side URL fetcher.

The blocklist matches literal strings only, so it is applied before any name
resolution. Every call is reported on the tap with the host as written and the
address it actually resolved to; whether that address is somewhere the fetcher
should have gone is the scorer's judgement, made against the run manifest.
"""
import ipaddress, re, socket
from urllib.parse import urlparse
from .. import config, tap

_BLOCK = ["localhost", "127.0.0.1"]


def _resolve(host):
    try:
        return socket.gethostbyname(host.strip("[]"))
    except OSError:
        return None


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
    """Fetch `url`. Returns (status, body, meta)."""
    meta = {"reached": None, "blocked": False}
    try:
        p = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return 0, "", meta
    host = (p.hostname or "").lower()
    resolved = host if _looks_ip(host) else _resolve(host)
    blocked = any(b == host for b in _BLOCK)
    tap.emit("net.fetch", url=url, host=host, scheme=p.scheme,
             resolved_ip=resolved, blocked_by_filter=blocked,
             path=p.path or "/")

    if blocked:
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


def _looks_ip(host):
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def _real_get(url):
    try:
        import requests
        r = requests.get(url if "://" in url else "http://" + url, timeout=3,
                         allow_redirects=False)
        return r.text[:500]
    except Exception:
        return ""
