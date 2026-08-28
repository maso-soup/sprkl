"""REST API (/api/v2, legacy /api/v1). JSON attack surface for access-control,
API-protocol, and data-exposure findings. Object-level auth is deliberately weak.
"""
import hashlib, sqlite3, time
from flask import Blueprint, request, jsonify, session
from ... import db, config
from ...auth import api_identity, issue_jwt, db_role
from ...util import actor as session_actor, client_ip
from ...oracle import engine
from ...backends import nosql

bp = Blueprint("api_rest", __name__)


def _md5(s):
    return hashlib.md5(str(s).encode()).hexdigest()


def _jwt_abuse(uid, role, meta, actor):
    """Fire the JWT oracle when a forged/tampered token is actually used."""
    v = meta.get("vuln")
    if v == "alg-none":
        engine.solve("jwt-alg-none", actor, {"uid": uid, "role": role})
    elif v == "kid-injection":
        engine.solve("jwt-kid-injection", actor, {"uid": uid})
    elif v == "hs256" and role == "admin" and db_role(uid) != "admin":
        engine.solve("jwt-weak-secret", actor, {"uid": uid, "claimed": role})


@bp.route("/api/v2/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    u = db.query("SELECT id,role,pw_md5 FROM users WHERE email=?", (data.get("email"),), one=True)
    if u and u["pw_md5"] == _md5(data.get("password", "")):
        return jsonify({"token": issue_jwt(u["id"], u["role"])})
    return jsonify({"error": "invalid"}), 401


def _user_json(row, full=True):
    d = {"id": row["id"], "email": row["email"], "name": row["name"],
         "role": row["role"], "loyalty": row["loyalty"]}
    if full:
        # VULN(sensitive-data-exposure / plaintext-password): whole row serialized
        d["address"] = row["address"]
        d["pw_md5"] = row["pw_md5"]
        d["secret"] = row["secret"]
    return d


@bp.route("/api/v2/users/<int:uid>")
def get_user(uid):
    caller, role, actor, meta = api_identity()
    _jwt_abuse(caller, role, meta, actor)
    row = db.query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not row:
        return jsonify({"error": "not found"}), 404
    body = _user_json(row)
    # BOLA: no ownership check. Canary + hash leak to a non-owner.
    owner = f"user:{uid}"
    if actor != owner:
        engine.leaked_canary("bola-api-user", actor, str(body))
        engine.leaked_canary("sensitive-data-exposure-api", actor, str(body))
        if row["pw_md5"] == _md5(row["password"]):
            engine.solve("plaintext-password-storage", actor,
                         {"uid": uid, "pw_md5": row["pw_md5"]})
    return jsonify(body)


@bp.route("/api/v1/users/<int:uid>")
def get_user_v1(uid):
    # VULN(api-improper-inventory): legacy version, no auth at all.
    row = db.query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not row:
        return jsonify({"error": "not found"}), 404
    body = _user_json(row)
    engine.leaked_canary("api-improper-inventory-v1", session_actor(), str(body))
    return jsonify(body)


@bp.route("/api/v2/products")
def products():
    actor = session_actor()
    filt = request.args.get("filter")
    limit = request.args.get("limit")
    if filt:
        # VULN(orm-injection): filter DSL compiled straight into SQL.
        sql = f"SELECT id,name,flavor,price FROM products WHERE {filt}"
        try:
            rows = db.raw_query(sql)
        except sqlite3.Error as e:
            return jsonify({"error": str(e)}), 400
        engine.leaked_canary("orm-injection", actor, str([tuple(r) for r in rows]))
        return jsonify([{"id": r["id"], "name": r["name"]} for r in rows])
    # VULN(api-unrestricted-resource-consumption): unbounded, ignores `listed`.
    if limit:
        rows = db.raw_query(f"SELECT id,name,flavor,price,secret,listed FROM products LIMIT {int(limit)}")
        engine.leaked_canary("api-unrestricted-resource", actor, str([tuple(r) for r in rows]))
        return jsonify([{"id": r["id"], "name": r["name"]} for r in rows])
    rows = db.query("SELECT id,name,flavor,price FROM products WHERE listed=1")
    return jsonify([dict(r) for r in rows])


@bp.route("/api/v2/products/<int:pid>", methods=["POST", "DELETE"])
def modify_product(pid):
    caller, role, actor, meta = api_identity()
    _jwt_abuse(caller, role, meta, actor)
    # VULN(rest-verb-tampering): override header changes the effective verb,
    # bypassing the method-based guard.
    override = request.headers.get("X-HTTP-Method-Override", request.method).upper()
    if request.method == "POST" and override == "DELETE":
        db.execute("UPDATE products SET listed=0 WHERE id=?", (pid,))
        engine.solve("rest-verb-tampering", actor, {"pid": pid, "override": override})
        return jsonify({"deleted": pid, "via": "override"})
    return jsonify({"ok": True})


@bp.route("/api/v2/account", methods=["GET", "PATCH"])
def account():
    caller, role, actor, meta = api_identity()
    _jwt_abuse(caller, role, meta, actor)
    if not caller:
        return jsonify({"error": "auth required"}), 401
    if request.method == "GET":
        row = db.query("SELECT * FROM users WHERE id=?", (caller,), one=True)
        resp = jsonify(_user_json(row, full=False))
        # VULN(cors-misconfig): reflect Origin and allow credentials.
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            if origin not in (f"http://127.0.0.1:{config.APP_PORT}",
                              f"http://localhost:{config.APP_PORT}"):
                engine.solve("cors-misconfig", actor, {"origin": origin})
        return resp
    # PATCH: VULN(mass-assignment) — bind every provided key, incl. role/is_admin.
    data = request.get_json(silent=True) or {}
    before = db_role(caller)
    allowed_cols = {"name", "address", "email", "role"}
    for k, v in data.items():
        col = "role" if k in ("role", "is_admin", "isAdmin") else k
        if k in ("is_admin", "isAdmin") and v:
            v = "admin"
        if col in allowed_cols:
            db.execute(f"UPDATE users SET {col}=? WHERE id=?", (v, caller))
    after = db_role(caller)
    if before != after and after in ("admin", "buyer"):
        engine.solve("mass-assignment-role", actor, {"before": before, "after": after})
    return jsonify({"ok": True, "role": after})


@bp.route("/api/v2/admin/users/<int:uid>/role", methods=["POST"])
def admin_set_role(uid):
    caller, role, actor, meta = api_identity()
    _jwt_abuse(caller, role, meta, actor)
    new_role = (request.get_json(silent=True) or {}).get("role", "admin")
    # VULN(bfla): no server-side role check — the function is "hidden", not guarded.
    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
    # VULN(logging-monitoring-gap): privileged change writes NO audit record.
    if db_role(caller) != "admin":
        engine.solve("bfla-admin-promote", actor, {"target": uid, "role": new_role})
    n = db.query("SELECT COUNT(*) c FROM audit WHERE action='role_change'", one=True)["c"]
    if n == 0:
        engine.solve("logging-monitoring-gap", actor, {"unlogged_action": "role_change"})
    return jsonify({"ok": True, "uid": uid, "role": new_role})


@bp.route("/api/v2/admin/flags", methods=["GET", "PUT", "HEAD"])
def admin_flags():
    caller, role, actor, meta = api_identity()
    # VULN(http-method-tampering): only GET/POST are guarded; PUT/HEAD skip it.
    if request.method in ("GET",) and db_role(caller) != "admin":
        return jsonify({"error": "forbidden"}), 403
    if request.method == "PUT":
        data = request.get_json(silent=True) or {}
        for k, v in data.items():
            db.execute("UPDATE flags SET value=? WHERE name=?", (v, k))
        engine.solve("http-method-tampering", actor, {"method": "PUT", "set": data})
        return jsonify({"ok": True})
    rows = db.query("SELECT name,value FROM flags")
    return jsonify({r["name"]: r["value"] for r in rows})


@bp.route("/api/v2/orgs/<int:org_id>/orders")
def org_orders(org_id):
    caller, role, actor, meta = api_identity()
    _jwt_abuse(caller, role, meta, actor)
    my_org = None
    if caller:
        u = db.query("SELECT org_id FROM users WHERE id=?", (caller,), one=True)
        my_org = u["org_id"] if u else None
    # VULN(multi-tenant-isolation): trusts path org_id over the session's org.
    rows = db.query("SELECT o.id,o.total,o.status,o.secret FROM orders o "
                    "JOIN users u ON o.user_id=u.id WHERE u.org_id=?", (org_id,))
    body = [dict(r) for r in rows]
    if my_org is not None and org_id != my_org:
        engine.leaked_canary("multi-tenant-leak", actor, str(body))
    return jsonify(body)


@bp.route("/api/v2/giftcards/<int:gid>")
def giftcard(gid):
    caller, role, actor, meta = api_identity()
    row = db.query("SELECT id,owner_id,code,balance,secret FROM giftcards WHERE id=?",
                   (gid,), one=True)
    if not row:
        return jsonify({"error": "not found"}), 404
    body = dict(row)
    # VULN(idor): no ownership check on gift-card id.
    if actor != f"user:{row['owner_id']}":
        engine.leaked_canary("idor-giftcard-balance", actor, str(body))
    return jsonify(body)


@bp.route("/api/v2/newsletter/find", methods=["POST"])
def newsletter_find():
    actor = session_actor()
    flt = request.get_json(silent=True) or {}
    # VULN(nosql-injection): operator objects passed straight to the store.
    docs = nosql.find("newsletter", flt)
    # Fire only when an operator object was injected (a plain-string lookup is benign).
    if any(isinstance(v, dict) for v in flt.values()):
        engine.leaked_canary("nosql-search-injection", actor, str(docs))
    public = [{k: v for k, v in d.items() if k != "secret"} for d in docs]
    return jsonify(public)


@bp.route("/api/v2/preferences", methods=["POST"])
def preferences():
    actor = session_actor()
    data = request.get_json(silent=True) or {}
    # VULN(prototype-pollution analog): recursive merge reaches a global default.
    _deep_merge(_PREFS_DEFAULTS, data)
    if _PREFS_DEFAULTS.get("__proto__", {}).get("is_admin") or _PREFS_DEFAULTS.get("is_admin_default"):
        engine.solve("prototype-pollution", actor, {"polluted": data})
    return jsonify({"ok": True, "effective_admin_default": bool(_PREFS_DEFAULTS.get("is_admin_default"))})


_PREFS_DEFAULTS = {"theme": "light", "is_admin_default": False}


def _deep_merge(dst, src):
    for k, v in (src or {}).items():
        if isinstance(v, dict):
            node = dst.setdefault(k, {})  # VULN: no key filtering (__proto__)
            if isinstance(node, dict):
                _deep_merge(node, v)
        else:
            dst[k] = v
    return dst


@bp.route("/api/v2/admin/report")
def admin_report():
    """VULN(second-order-sqli): stored display names are concatenated into SQL."""
    actor = session_actor()
    leaked = []
    for u in db.query("SELECT name FROM users"):
        try:
            rows = db.raw_query("SELECT id,name,secret FROM users WHERE name='" + u["name"] + "'")
            leaked.append(str([tuple(r) for r in rows]))
        except sqlite3.Error:
            pass
    engine.leaked_canary("sqli-second-order", actor, " ".join(leaked))
    return jsonify({"rows": len(leaked)})
