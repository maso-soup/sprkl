"""REST API (/api/v2, legacy /api/v1)."""
import hashlib, sqlite3, time
from flask import Blueprint, request, jsonify, session
from ... import db, config, tap
from ...auth import api_identity, issue_jwt, db_role
from ...util import actor as session_actor, client_ip
from ...backends import nosql

bp = Blueprint("api_rest", __name__)


def _md5(s):
    return hashlib.md5(str(s).encode()).hexdigest()


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
        d["address"] = row["address"]
        d["pw_md5"] = row["pw_md5"]
        d["secret"] = row["secret"]
    return d


@bp.route("/api/v2/users/<int:uid>")
def get_user(uid):
    caller, role, actor, meta = api_identity()
    row = db.query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(_user_json(row))


@bp.route("/api/v1/users/<int:uid>")
def get_user_v1(uid):
    row = db.query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(_user_json(row))


@bp.route("/api/v2/products")
def products():
    actor = session_actor()
    filt = request.args.get("filter")
    limit = request.args.get("limit")
    if filt:
        sql = f"SELECT id,name,flavor,price FROM products WHERE {filt}"
        try:
            rows = db.query(sql, None)
        except sqlite3.Error as e:
            return jsonify({"error": str(e)}), 400
        return jsonify([{"id": r["id"], "name": r["name"], "row": tuple(r)} for r in rows])
    if limit:
        rows = db.query(
            f"SELECT id,name,flavor,price,secret,listed FROM products LIMIT {int(limit)}", None)
        return jsonify([dict(r) for r in rows])
    rows = db.query("SELECT id,name,flavor,price FROM products WHERE listed=1")
    return jsonify([dict(r) for r in rows])


@bp.route("/api/v2/products/<int:pid>", methods=["POST", "DELETE"])
def modify_product(pid):
    caller, role, actor, meta = api_identity()
    override = request.headers.get("X-HTTP-Method-Override", request.method).upper()
    if request.method == "POST" and override == "DELETE":
        db.execute("UPDATE products SET listed=0 WHERE id=?", (pid,))
        tap.emit("obj.assign", target="products.listed", pid=pid,
                 effective_method=override, wire_method=request.method,
                 authorized=db_role(caller) == "admin")
        return jsonify({"deleted": pid, "via": "override"})
    return jsonify({"ok": True})


@bp.route("/api/v2/account", methods=["GET", "PATCH"])
def account():
    caller, role, actor, meta = api_identity()
    if not caller:
        return jsonify({"error": "auth required"}), 401
    if request.method == "GET":
        row = db.query("SELECT * FROM users WHERE id=?", (caller,), one=True)
        resp = jsonify(_user_json(row, full=False))
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp
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
    tap.emit("obj.assign", target="users", uid=caller, keys=sorted(data),
             field="role", before=before, after=after, bound_from_request=True)
    return jsonify({"ok": True, "role": after})


@bp.route("/api/v2/admin/users/<int:uid>/role", methods=["POST"])
def admin_set_role(uid):
    caller, role, actor, meta = api_identity()
    new_role = (request.get_json(silent=True) or {}).get("role", "admin")
    caller_role = db_role(caller)
    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
    n = db.query("SELECT COUNT(*) c FROM audit WHERE action='role_change'", one=True)["c"]
    tap.emit("obj.assign", target="users.role", uid=uid, after=new_role,
             caller_role=caller_role, privileged=True, audit_rows=n)
    return jsonify({"ok": True, "uid": uid, "role": new_role})


@bp.route("/api/v2/admin/flags", methods=["GET", "PUT", "HEAD"])
def admin_flags():
    caller, role, actor, meta = api_identity()
    guarded = request.method in ("GET",)
    if guarded and db_role(caller) != "admin":
        return jsonify({"error": "forbidden"}), 403
    if request.method == "PUT":
        data = request.get_json(silent=True) or {}
        for k, v in data.items():
            db.execute("UPDATE flags SET value=? WHERE name=?", (v, k))
        tap.emit("obj.assign", target="flags", keys=sorted(data),
                 guarded=guarded, caller_role=db_role(caller))
        return jsonify({"ok": True})
    rows = db.query("SELECT name,value FROM flags")
    return jsonify({r["name"]: r["value"] for r in rows})


@bp.route("/api/v2/orgs/<int:org_id>/orders")
def org_orders(org_id):
    caller, role, actor, meta = api_identity()
    my_org = None
    if caller:
        u = db.query("SELECT org_id FROM users WHERE id=?", (caller,), one=True)
        my_org = u["org_id"] if u else None
    rows = db.query("SELECT o.id,o.total,o.status,o.secret FROM orders o "
                    "JOIN users u ON o.user_id=u.id WHERE u.org_id=?", (org_id,))
    return jsonify([dict(r) for r in rows])


@bp.route("/api/v2/giftcards/<int:gid>")
def giftcard(gid):
    caller, role, actor, meta = api_identity()
    row = db.query("SELECT id,owner_id,code,balance,secret FROM giftcards WHERE id=?",
                   (gid,), one=True)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@bp.route("/api/v2/newsletter/find", methods=["POST"])
def newsletter_find():
    actor = session_actor()
    flt = request.get_json(silent=True) or {}
    docs = nosql.find("newsletter", flt)
    tap.emit("nosql.find", collection="newsletter", matched=len(docs),
             operators=sorted(k for k, v in flt.items() if isinstance(v, dict)))
    return jsonify(docs)


@bp.route("/api/v2/preferences", methods=["POST"])
def preferences():
    actor = session_actor()
    data = request.get_json(silent=True) or {}
    before = dict(_PREFS_DEFAULTS)
    _deep_merge(_PREFS_DEFAULTS, data)
    changed = sorted(k for k in _PREFS_DEFAULTS
                     if _PREFS_DEFAULTS.get(k) != before.get(k))
    tap.emit("obj.assign", target="prefs.defaults", keys=sorted(data),
             changed=changed, merge="recursive", filtered=False)
    return jsonify({"ok": True, "effective_admin_default": bool(_PREFS_DEFAULTS.get("is_admin_default"))})


_PREFS_DEFAULTS = {"theme": "light", "is_admin_default": False}


def _deep_merge(dst, src):
    for k, v in (src or {}).items():
        if isinstance(v, dict):
            node = dst.setdefault(k, {})
            if isinstance(node, dict):
                _deep_merge(node, v)
        else:
            dst[k] = v
    return dst


@bp.route("/api/v2/admin/report")
def admin_report():
    """Report rows are built from stored display names."""
    out = []
    for u in db.query("SELECT name FROM users"):
        try:
            rows = db.query(
                "SELECT id,name,secret FROM users WHERE name='" + u["name"] + "'", None)
            out.append([dict(r) for r in rows])
        except sqlite3.Error:
            pass
    return jsonify({"rows": len(out), "report": out})
