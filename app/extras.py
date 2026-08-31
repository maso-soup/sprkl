"""Config/components surfaces and client-side landing pages."""
from flask import (Blueprint, request, jsonify, render_template, Response,
                   make_response, redirect)
from . import config, db, tap
from .util import actor
from .backends import objstore, cache as _cache

bp = Blueprint("extras", __name__)

ASSETS = config.SPEC.get("assets", {})


@bp.route("/debug")
def debug():
    return jsonify({"FLASK_SECRET": config.FLASK_SECRET,
                    "JWT_SECRET": config.JWT_SECRET,
                    "SPRKL_DEBUG_SECRET": ASSETS.get("debug", ""),
                    "DB_PATH": config.DB_PATH})


@bp.route("/api/v2/echo")
def echo():
    n = request.args.get("n", "1")
    try:
        return {"value": int(n)}
    except ValueError:
        tb = ("Traceback (most recent call last):\n"
              f"  File '{config.BASE_DIR}/app/extras.py', line 1, in echo\n"
              f"ValueError: invalid literal for int(): {n!r}\n"
              f"CONFIG {ASSETS.get('debug','')}")
        return Response(tb, status=500, mimetype="text/plain")


@bp.route("/audit/security-headers")
def audit_headers():
    return make_response(jsonify({"note": "check response headers"}))


@bp.route("/status")
def status():
    if request.args.get("format") == "json":
        resp = make_response(jsonify({"app": "sprkl", "framework": "SprklKit/1.0.0"}))
    else:
        resp = make_response(render_template("status.html"))
    resp.headers["X-Powered-By"] = f"SprklKit/1.0.0 ({ASSETS.get('cve','')})"
    resp.headers["Server"] = "Werkzeug SprklKit/1.0.0"
    return resp


@bp.route("/api/v2/advisory")
def advisory():
    return {"query": request.args.get("q", ""), "advisories": []}


@bp.route("/.env")
def dotenv():
    body = (f"FLASK_SECRET={config.FLASK_SECRET}\nJWT_SECRET={config.JWT_SECRET}\n"
            f"AWS_SECRET={ASSETS.get('env','')}\n")
    return Response(body, mimetype="text/plain")


@bp.route("/backup.zip")
def backup_zip():
    return Response(f"SPRKL source backup — contains {ASSETS.get('env','')}",
                    mimetype="application/zip")


@bp.route("/assets/")
def assets_list():
    if request.args.get("list") == "1":
        return {"keys": objstore.list_keys()}
    return {"keys": []}


@bp.route("/assets/<path:key>")
def assets_get(key):
    data = objstore.get(key)
    if data is None:
        return {"error": "not found"}, 404
    return Response(data if isinstance(data, (bytes, str)) else str(data),
                    mimetype="application/octet-stream")


@bp.route("/api/v2/keycheck")
def keycheck():
    key = request.args.get("key", "")
    return {"valid": key == ASSETS.get("jskey", "")}


@bp.route("/go")
def go():
    return redirect(request.args.get("url", "/"))


@bp.route("/promo")
def promo():
    return render_template("promo.html", msg=request.args.get("msg", ""))


@bp.route("/embed/widget")
def widget():
    return render_template("widget.html", msg=request.args.get("msg", ""))


@bp.route("/retail/account/<path:pseudo>")
def cached_profile(pseudo):
    """A fake static extension makes a private page look cacheable."""
    key = "cache:" + request.path
    cached = _cache.get(key)
    if pseudo.endswith(".css"):
        if cached is None:
            row = db.query("SELECT email,secret FROM users WHERE id=1", one=True)
            pii = {"email": row["email"], "secret": row["secret"]}
            _cache.put(key, pii)
            tap.emit("cache.store", store="page", key=key, hit=False)
            return jsonify(pii)
        tap.emit("cache.store", store="page", key=key, hit=True)
        return jsonify(cached)
    return jsonify({"private": True})


@bp.route("/cached-home")
def cached_home():
    """X-Forwarded-Host is reflected but is not part of the cache key."""
    key = "home"
    cached = _cache.get(key)
    xfh = request.headers.get("X-Forwarded-Host")
    if xfh:
        _cache.put(key, xfh)
        tap.emit("cache.store", store="page", key=key, hit=False, keyed_on_header=False)
        return jsonify({"resource_host": xfh})
    if cached:
        tap.emit("cache.store", store="page", key=key, hit=True, keyed_on_header=False)
        return jsonify({"resource_host": cached})
    return jsonify({"resource_host": request.host})


@bp.route("/ws/notifications")
def ws_notifications():
    """Long-poll stand-in for a WebSocket subscription: no Origin check, no auth."""
    uid = request.args.get("uid", type=int) or 1
    row = db.query("SELECT secret FROM users WHERE id=?", (uid,), one=True)
    notes = [{"to": uid, "text": "Order shipped",
              "secret": row["secret"] if row else ""}]
    tap.emit("ws.message", channel=f"user:{uid}",
             origin=request.headers.get("Origin", ""), authenticated=False)
    return jsonify({"channel": f"user:{uid}", "messages": notes})
