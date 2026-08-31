"""Admin console — hidden panel, unlinked; reached only by browsing to /admin.

One blueprint serves both the console chrome and the action endpoints.
"""
import subprocess, os, io, zipfile, base64, pickle, pickletools
from flask import Blueprint, render_template, session, redirect, request
from ... import db, config, tap
from ...util import actor
from ...backends import ldap, nosql, fetcher

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _guard():
    return None if session.get("admin") else redirect("/admin")


# ---- console chrome (GUI pages) --------------------------------------------

@bp.route("")
@bp.route("/")
def login():
    if session.get("admin"):
        return redirect("/admin/console")
    return render_template("admin_login.html", error=None)


@bp.route("/console")
def console():
    g = _guard()
    if g:
        return g
    return render_template("admin_console.html", role=session.get("admin_role"))


@bp.route("/inventory")
def inventory():
    g = _guard()
    if g:
        return g
    return render_template("admin_inventory.html")


@bp.route("/directory")
def directory():
    g = _guard()
    if g:
        return g
    u = request.args.get("u")
    results = None
    if u is not None:
        flt = "(uid=" + u + ")"
        results = ldap.search(flt)
        tap.emit("ldap.search", filter=flt, arg=u, matched=len(results or []))
    return render_template("admin_directory.html", u=u, results=results)


@bp.route("/users")
def users():
    g = _guard()
    if g:
        return g
    rows = db.query("SELECT id,name,email,role,org_id FROM users")
    flags = db.query("SELECT name,value FROM flags")
    return render_template("admin_users.html", users=rows, flags=flags)


@bp.route("/integrations")
def integrations():
    g = _guard()
    if g:
        return g
    return render_template("admin_integrations.html")


@bp.route("/tools")
def tools():
    g = _guard()
    if g:
        return g
    return render_template("admin_tools.html")


@bp.route("/themes")
def themes():
    g = _guard()
    if g:
        return g
    return render_template("admin_themes.html")


@bp.route("/prefs")
def prefs():
    g = _guard()
    if g:
        return g
    return render_template("admin_prefs.html")


@bp.route("/inbox")
@bp.route("/support/inbox")
def inbox():
    g = _guard()
    if g:
        return g
    msgs = db.query("SELECT email,subject,message FROM contacts ORDER BY id DESC")
    return render_template("admin_inbox.html", msgs=msgs)


@bp.route("/orders")
def orders():
    g = _guard()
    if g:
        return g
    return render_template("admin_orders.html")


# ---- authentication --------------------------------------------------------

@bp.route("/login", methods=["GET", "POST"])
def signin():
    if request.method == "GET":
        return redirect("/admin")
    user = request.form.get("username", "")
    pw = request.form.get("password", "")
    row = db.query("SELECT id,email,role FROM users WHERE email=? AND password=? "
                   "AND role IN ('admin','buyer')", (user, pw), one=True)
    if not row and user == "admin" and pw == "admin":
        row = db.query("SELECT id,email,role FROM users WHERE role='admin'", one=True)
    if row:
        tap.emit("auth.result", mechanism="password", ok=True,
                 password_verified=True, principal=f"user:{row['id']}",
                 user=user, credential=pw, role=row["role"])
        session["admin"] = row["id"]
        session["admin_role"] = row["role"]
        return redirect("/admin/console")
    tap.emit("auth.result", mechanism="password", ok=False,
             password_verified=False, principal=None, user=user)
    return render_template("admin_login.html", error="Invalid admin credentials")


@bp.route("/dashboard")
def dashboard():
    return redirect("/admin/console")


@bp.route("/api/login", methods=["POST"])
def api_login():
    """JSON login against the document-store admin collection."""
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    flt = {"username": username, "password": password}
    docs = nosql.find("admin_users", flt)
    tap.emit("nosql.find", collection="admin_users", matched=len(docs),
             operators=sorted(k for k, v in flt.items() if isinstance(v, dict)))
    if docs:
        d = docs[0]
        tap.emit("auth.result", mechanism="document-store", ok=True,
                 password_verified=isinstance(password, str)
                 and d.get("password") == password,
                 principal=f"admin:{d.get('username')}", user=username,
                 role=d.get("role"))
        session["admin"] = d.get("username")
        session["admin_role"] = d.get("role")
        return {"ok": True, "role": d.get("role")}
    return {"ok": False}, 401


# ---- tools -----------------------------------------------------------------

@bp.route("/tools/ping", methods=["GET", "POST"])
def ping():
    g = _guard()
    if g:
        return g
    host = request.values.get("host", "")
    output = ""
    if host:
        cmd = "ping -c 1 " + host
        tap.emit("proc.exec", cmd=cmd, shell=True, arg=host,
                 stdout_returned=False, template="ping -c 1 {}")
        try:
            subprocess.run(cmd, shell=True, timeout=8,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        output = "Connectivity check dispatched."
    return {"output": output}


@bp.route("/labels/generate", methods=["POST"])
def labels_generate():
    g = _guard()
    if g:
        return g
    filename = request.values.get("filename", "label")
    cmd = "echo LABEL:" + filename
    out = subprocess.run(cmd, shell=True, capture_output=True,
                         text=True, timeout=8).stdout
    extra = [l for l in out.splitlines() if l and not l.startswith("LABEL:")]
    tap.emit("proc.exec", cmd=cmd, shell=True, arg=filename,
             stdout_returned=True, template="echo LABEL:{}",
             extra_output_lines=len(extra), extra_output=extra[:3])
    return {"output": out}


@bp.route("/tools/mfa-skip")
def mfa_skip():
    if session.get("pre_mfa") and not session.get("mfa_done"):
        session["admin"] = session.get("pre_mfa")
        session["admin_role"] = "admin"
        tap.emit("auth.result", mechanism="mfa", ok=True, password_verified=False,
                 principal=f"user:{session.get('pre_mfa')}",
                 steps_completed=["password"], steps_required=["password", "otp"])
        return {"ok": True, "console": "granted"}
    return {"ok": False}, 403


@bp.route("/mfa/begin", methods=["POST"])
def mfa_begin():
    u = db.query("SELECT id FROM users WHERE role='admin'", one=True)
    session["pre_mfa"] = u["id"]
    return {"ok": True, "next": "/admin/tools/mfa-skip (should require OTP)"}


# ---- inventory / files / deserialization -----------------------------------

@bp.route("/inventory/import", methods=["POST"])
def inventory_import():
    g = _guard()
    if g:
        return g
    xml_data = request.get_data(as_text=True)
    import re as _re
    m = _re.search(r'<!ENTITY\s+\w+\s+SYSTEM\s+"file://([^"]+)"', xml_data)
    if m:
        try:
            content = open(m.group(1)).read()
        except OSError:
            content = ""
        tap.emit("xml.parse", external_entities=True, entity_uri=m.group(1),
                 resolved=m.group(1), root="/", bytes_read=len(content))
        return {"imported": 0, "entity": content[:200]}
    return {"imported": xml_data.count("<product")}


@bp.route("/inventory/import-zip", methods=["POST"])
def import_zip():
    g = _guard()
    if g:
        return g
    f = request.files.get("file")
    if not f:
        return {"error": "no file"}, 400
    dest = os.path.join(config.DATA_DIR, "import")
    os.makedirs(dest, exist_ok=True)
    try:
        z = zipfile.ZipFile(io.BytesIO(f.read()))
    except zipfile.BadZipFile:
        return {"error": "bad zip"}, 400
    for name in z.namelist():
        real = os.path.realpath(os.path.join(dest, name))
        tap.emit("archive.extract", entry=name, resolved=real,
                 root=os.path.realpath(dest))
    return {"entries": z.namelist()}


@bp.route("/render")
def render_theme():
    g = _guard()
    if g:
        return g
    theme = request.args.get("theme", "default")
    base = os.path.join(config.DATA_DIR, "themes")
    os.makedirs(base, exist_ok=True)
    path = os.path.normpath(os.path.join(base, theme + ".html"))
    real = os.path.realpath(path)
    root = os.path.realpath(base)
    tap.emit("tmpl.render", from_path=True, requested=theme,
             resolved=real, root=root)
    if not real.startswith(root):
        try:
            return open(real).read()
        except OSError:
            return {"included": theme}
    return {"theme": theme}


@bp.route("/prefs/import", methods=["POST"])
def prefs_import():
    g = _guard()
    if g:
        return g
    blob = request.values.get("prefs") or request.cookies.get("prefs", "")
    try:
        raw = base64.b64decode(blob)
    except Exception:
        return {"error": "bad blob"}, 400
    # The opcode list is raw material: what the payload contains, not what it means.
    try:
        ops = [op.name for op, _arg, _pos in pickletools.genops(raw)]
    except Exception:
        ops = []
    tap.emit("deser.load", fmt="pickle", opcodes=",".join(ops[:64]),
             bytes_len=len(raw))
    try:
        pickle.loads(raw)  # noqa: S301
    except Exception:
        pass
    return {"ok": True}


# ---- integrations / reports / access-control -------------------------------

@bp.route("/integrations/webhook/test", methods=["POST"])
def webhook_test():
    g = _guard()
    if g:
        return g
    fetcher.fetch(request.form.get("url", ""))
    return {"ok": True, "dispatched": True}


@bp.route("/integrations/fx-sync", methods=["POST"])
def fx_sync():
    g = _guard()
    if g:
        return g
    fetcher.fetch(request.form.get("upstream", ""))
    return {"ok": True, "synced": True}


@bp.route("/reports/financials")
def reports_financials():
    rows = db.query("SELECT id,total,secret FROM orders")
    return {"report": "financials", "orders": [dict(r) for r in rows]}


@bp.route("/public/<path:sub>")
def public_proxy(sub):
    """The allowlist matches the raw prefix; normalisation happens afterwards."""
    raw = request.full_path
    if "..%2f" in raw.lower() or "..%2F" in raw or "../" in sub:
        if "admin" in sub or "admin" in raw.lower():
            return {"console": "admin",
                    "secret": config.SPEC.get("planted", {}).get("admin_console", "")}
    return {"public": sub}
