"""Shared helpers: actor identity and the cookie MAC."""
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
    """Trusts X-Forwarded-For. The proxy records the real peer separately."""
    return request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")


def weak_mac(data: str) -> str:
    return hashlib.md5(config.COOKIE_MAC_SECRET + data.encode()).hexdigest()
