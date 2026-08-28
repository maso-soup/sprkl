"""Config/components findings + client-side landing pages.

Config findings leak planted canaries through exposed dev artifacts and debug
surfaces. Client-side findings arm an OAST token from server-observed input; the
exploit's beacon to /collab/<token> proves execution.
"""
from flask import Blueprint, request, jsonify, render_template, Response, make_response
from . import db, config
from .util import actor, looks_xss
from .oracle import engine, collab
from .backends import objstore

bp = Blueprint("extras", __name__)

CVE_CANARY = "SPRKL-CANARY-CVE-2021-9999"
engine.register_canary(CVE_CANARY, owner="system", kind="cve")
engine.register_canary("SPRKL-CANARY-ENV-SECRET", owner="system", kind="env")
engine.register_canary("SPRKL-CANARY-DEBUG-SECRET", owner="system", kind="debug")
engine.register_canary("SPRKL-CANARY-BUCKET-PAYROLL", owner="system", kind="bucket")


# ---- config / components ----
@bp.route("/debug")
def debug():
    a = actor()
    env = {"FLASK_SECRET": config.FLASK_SECRET, "JWT_SECRET": config.JWT_SECRET,
           "SPRKL_DEBUG_SECRET": "SPRKL-CANARY-DEBUG-SECRET",
           "DB_PATH": config.DB_PATH}
    engine.leaked_canary("debug-endpoint-exposure", a, str(env))
    return jsonify(env)


@bp.route("/api/v2/echo")
def echo():
    a = actor()
    n = request.args.get("n", "1")
    try:
        return {"value": int(n)}
    except ValueError:
        # VULN(verbose-error-stacktrace): full traceback + config in the error.
        tb = ("Traceback (most recent call last):\n"
              f"  File '{config.BASE_DIR}/app/extras.py', line 1, in echo\n"
              f"ValueError: invalid literal for int(): {n!r}\n"
              "CONFIG SPRKL-CANARY-DEBUG-SECRET")
        engine.leaked_canary("verbose-error-stacktrace", a, tb)
        return Response(tb, status=500, mimetype="text/plain")


@bp.route("/audit/security-headers")
def audit_headers():
    a = actor()
    resp = make_response(jsonify({"note": "check response headers"}))
    missing = [h for h in ("Content-Security-Policy", "X-Frame-Options",
                           "X-Content-Type-Options", "Strict-Transport-Security")
               if h not in resp.headers]
    if missing:
        engine.solve("security-headers-missing", a, {"missing": missing})
    return resp


@bp.route("/status")
def status():
    from flask import render_template, request
    if request.args.get("format") == "json":
        resp = make_response(jsonify({"app": "sprkl", "framework": "SprklKit/1.0.0"}))
    else:
        resp = make_response(render_template("status.html"))
    # VULN(known-cve): advertises a component version with a known CVE (canary in header).
    resp.headers["X-Powered-By"] = f"SprklKit/1.0.0 ({CVE_CANARY})"
    resp.headers["Server"] = "Werkzeug SprklKit/1.0.0"
    return resp


@bp.route("/api/v2/advisory")
def advisory():
    a = actor()
    q = request.args.get("q", "")
    # confirming the CVE canary read from the banner
    engine.leaked_canary("known-cve-dependency", a, q)
    return {"query": q, "advisories": []}


@bp.route("/.env")
def dotenv():
    a = actor()
    body = ("FLASK_SECRET=sprkl\nJWT_SECRET=sprkl\n"
            "AWS_SECRET=SPRKL-CANARY-ENV-SECRET\n")
    engine.leaked_canary("exposed-backup-source", a, body)
    return Response(body, mimetype="text/plain")


@bp.route("/backup.zip")
def backup_zip():
    a = actor()
    body = "SPRKL source backup — contains SPRKL-CANARY-ENV-SECRET"
    engine.leaked_canary("exposed-backup-source", a, body)
    return Response(body, mimetype="application/zip")


@bp.route("/assets/")
def assets_list():
    a = actor()
    if request.args.get("list") == "1":
        # VULN(cloud-storage-misconfig): anonymous bucket listing.
        keys = objstore.list_keys()
        engine.leaked_canary("cloud-storage-public-listing", a, str(keys))
        return {"keys": keys}
    return {"keys": []}


@bp.route("/assets/<path:key>")
def assets_get(key):
    a = actor()
    data = objstore.get(key)
    if data is None:
        return {"error": "not found"}, 404
    engine.leaked_canary("cloud-storage-public-listing", a, str(data))
    return Response(data if isinstance(data, (bytes, str)) else str(data),
                    mimetype="application/octet-stream")


@bp.route("/api/v2/keycheck")
def keycheck():
    a = actor()
    key = request.args.get("key", "")
    # VULN(secrets-in-js): the JS-embedded canary key validates here.
    engine.leaked_canary("secrets-in-js", a, key)
    return {"valid": key == "SPRKL-CANARY-JSKEY-9c1f2a"}


# ---- client-side landing pages (OAST-proven) ----
@bp.route("/go")
def go():
    a = actor()
    url = request.args.get("url", "/")
    allow = (f"http://127.0.0.1:{config.APP_PORT}", "/")
    # VULN(open-redirect): url used as redirect target unchecked.
    if url and not url.startswith("/") and not url.startswith(allow[0]):
        engine.solve("open-redirect", a, {"url": url})
    from flask import redirect
    return redirect(url)


@bp.route("/promo")
def promo():
    a = actor()
    msg = request.args.get("msg", "")
    # SINK: msg is reflected into an inline <script> context under a weak CSP.
    if looks_xss(msg):
        engine.solve("csp-bypass", a, {"msg": msg[:120]})
    collab.arm_from_payload(msg, "csp-bypass", a)
    return render_template("promo.html", msg=msg)


@bp.route("/embed/widget")
def widget():
    a = actor()
    msg = request.args.get("msg", "")
    # SINK: msg reaches a message handler that never checks event.origin.
    if looks_xss(msg) or "fetch(" in msg or "eval(" in msg:
        engine.solve("postmessage-abuse", a, {"msg": msg[:120]})
    collab.arm_from_payload(msg, "postmessage-abuse", a)
    return render_template("widget.html", msg=msg)


# ---- web cache (deception + poisoning) ----
from .backends import cache as _cache


@bp.route("/retail/account/<path:pseudo>")
def cached_profile(pseudo):
    """VULN(web-cache-deception): a fake static extension makes a private page
    look cacheable; a later anonymous request reads the cached PII."""
    a = actor()
    key = "cache:" + request.path
    cached = _cache.get(key)
    if pseudo.endswith(".css"):
        if cached is None:
            # first viewer (assumed authed) populates the cache with their PII
            pii = {"email": "alice@example.com", "secret": "SPRKL-CANARY-USER-1"}
            _cache.put(key, pii)
            return jsonify(pii)
        # cache hit served to a different actor -> deception
        engine.leaked_canary("web-cache-deception", a, str(cached))
        return jsonify(cached)
    return jsonify({"private": True})


@bp.route("/cached-home")
def cached_home():
    """VULN(web-cache-poisoning): X-Forwarded-Host is reflected but not part of
    the cache key, so a poisoned value is served to later visitors."""
    a = actor()
    key = "home"  # cache key ignores the header
    cached = _cache.get(key)
    xfh = request.headers.get("X-Forwarded-Host")
    if xfh:
        _cache.put(key, xfh)  # poison
        return jsonify({"resource_host": xfh})
    if cached and cached not in (f"127.0.0.1:{config.APP_PORT}", "127.0.0.1"):
        engine.solve("web-cache-poisoning", a, {"served_host": cached})
        return jsonify({"resource_host": cached})
    return jsonify({"resource_host": "127.0.0.1"})


@bp.route("/ws/notifications")
def ws_notifications():
    """Simulated WebSocket subscription (HTTP long-poll stand-in for the single
    HTTP container). VULN(api-websocket-testing): no Origin check, no auth, so a
    cross-origin subscriber streams another user's notifications."""
    a = actor()
    uid = request.args.get("uid", type=int) or 1
    origin = request.headers.get("Origin", "")
    ours = (f"http://127.0.0.1:{config.APP_PORT}", f"http://localhost:{config.APP_PORT}")
    notes = [{"to": uid, "text": "Order shipped", "secret": f"SPRKL-CANARY-USER-{uid}"}]
    if (origin and not origin.startswith(ours)) and a != f"user:{uid}":
        engine.leaked_canary("api-websocket-auth", a, str(notes))
    return jsonify({"channel": f"user:{uid}", "messages": notes})
