"""Shared helpers: actor identity + a weak MAC used by several findings."""
import os, hashlib, hmac
from flask import request, session
from . import config


def actor():
    """Stable identity for the current tester.

    Logged-in users are `user:<id>`; otherwise a per-session anonymous id.
    This is what solves are attributed to and how "unauthorized actor" is judged.
    """
    if session.get("uid"):
        return f"user:{session['uid']}"
    if session.get("admin"):
        return f"admin:{session['admin']}"
    sid = session.get("sid")
    if not sid:
        sid = session["sid"] = os.urandom(8).hex()
    return f"anon:{sid}"


def client_ip():
    # VULN: trusts X-Forwarded-For (rate-limit-bypass, log spoofing)
    return request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")


def weak_mac(data: str) -> str:
    # VULN(hash-length-extension): md5(secret || data), not HMAC
    return hashlib.md5(config.COOKIE_MAC_SECRET + data.encode()).hexdigest()


import re as _re

_XSS_RE = _re.compile(
    r"<script|</script|onerror\s*=|onload\s*=|onmouseover\s*=|onfocus\s*=|"
    r"<img|<svg|<iframe|javascript:|<body|<video|<audio|<details", _re.I)


def looks_xss(s):
    """True if the string carries an executable HTML/JS vector."""
    return bool(s) and bool(_XSS_RE.search(s))


_MUTATION_RE = _re.compile(r"<noscript|<template|<xmp|<math|<style|<textarea|<title", _re.I)


def looks_mutation_xss(s):
    """mXSS vectors that are inert until the browser re-parses them."""
    return bool(s) and bool(_MUTATION_RE.search(s))


_DANGLING_RE = _re.compile(r"<\w+[^>]*=\s*['\"][^'\"]*$")


def looks_dangling_markup(s):
    """An unterminated attribute quote that will swallow following markup."""
    return bool(s) and bool(_DANGLING_RE.search(s.strip()))


def dangerous_pickle(raw: bytes) -> bool:
    """True if a pickle references a code-exec primitive (GLOBAL to os/subprocess/etc)."""
    if not raw:
        return False
    needles = [b"posix\n", b"nt\n", b"os\n", b"system", b"subprocess", b"popen",
               b"__builtin__", b"builtins", b"\neval", b"\nexec", b"getattr",
               b"commands", b"pty", b"socket"]
    return any(n in raw for n in needles)
