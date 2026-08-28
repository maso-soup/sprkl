"""Admin console — hidden panel (unlinked, unhinted; reached only by browsing to
/admin). One blueprint serves both the console chrome (GUI pages) and the
underlying action endpoints, all under /admin/*. These endpoints are the
unchanged vulnerability sinks.
"""
import subprocess, os, io, zipfile, base64, pickle
from flask import Blueprint, render_template, session, redirect, request
from ... import db, config
from ...util import actor, dangerous_pickle
from ...oracle import engine, collab
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
        # VULN(ldap-injection): filter built by string concatenation.
        flt = "(uid=" + u + ")"
        results = ldap.search(flt)
        engine.leaked_canary("ldap-injection", actor(), str(results))
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
    # VULN(blind-xss): stored contact messages rendered raw to staff.
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
        # VULN(default-creds-admin): admin/admin works out of the box.
        if user == "admin" and pw == "admin":
            engine.solve("default-creds-admin", actor(), {"username": user})
        session["admin"] = row["id"]
        session["admin_role"] = row["role"]
        return redirect("/admin/console")
    return render_template("admin_login.html", error="Invalid admin credentials")


@bp.route("/dashboard")
def dashboard():
    return redirect("/admin/console")


@bp.route("/api/login", methods=["POST"])
def api_login():
    """VULN(nosql-login-bypass): JSON login against the Mongo-style admin store;
    operator objects like {"$ne": null} are honored."""
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    docs = nosql.find("admin_users", {"username": username, "password": password})
    if docs:
        d = docs[0]
        if not isinstance(password, str) or d.get("password") != password:
            engine.solve("nosql-login-bypass", actor(),
                         {"username": username, "password": password})
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
        import re as _re
        a = actor()
        # VULN(blind-command-injection): host concatenated into a shell command.
        cmd = "ping -c 1 " + host
        # SINK-side detection: the server runs the shell, so it observes an injected
        # extra command regardless of where the tester's callback goes.
        if _re.search(r'(;|\|\||&&|\||\$\(|`)\s*\S', host):
            engine.solve("blind-command-injection", a, {"host": host, "cmd": cmd})
        collab.arm_from_payload(host, "blind-command-injection", a)  # bonus /collab path
        try:
            subprocess.run(cmd, shell=True, timeout=8,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        output = "Connectivity check dispatched."  # blind: no command output shown
    return {"output": output}


@bp.route("/labels/generate", methods=["POST"])
def labels_generate():
    g = _guard()
    if g:
        return g
    filename = request.values.get("filename", "label")
    # VULN(os-command-injection): filename concatenated into a shell command.
    out = subprocess.run("echo LABEL:" + filename, shell=True,
                         capture_output=True, text=True, timeout=8).stdout
    marker_lines = [l for l in out.splitlines() if l and not l.startswith("LABEL:")]
    if any(c in filename for c in [";", "|", "&", "$(", "`"]) and marker_lines:
        engine.solve("os-command-injection", actor(),
                     {"filename": filename, "extra_output": marker_lines[:3]})
    return {"output": out}


@bp.route("/tools/mfa-skip")
def mfa_skip():
    # VULN(mfa-bypass): the console trusts a pre-MFA session state.
    a = actor()
    if session.get("pre_mfa") and not session.get("mfa_done"):
        session["admin"] = session.get("pre_mfa")
        session["admin_role"] = "admin"
        engine.solve("mfa-bypass-skip-step", a, {"skipped": True})
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
    a = actor()
    xml_data = request.get_data(as_text=True)
    import re as _re
    # VULN(xxe-xml-import): external entities enabled; SYSTEM file:// entities resolved.
    m = _re.search(r'<!ENTITY\s+\w+\s+SYSTEM\s+"file://([^"]+)"', xml_data)
    if m:
        try:
            content = open(m.group(1)).read()
        except OSError:
            content = ""
        engine.leaked_canary("xxe-xml-import", a, content)
        return {"imported": 0, "entity": content[:200]}
    return {"imported": xml_data.count("<product")}


@bp.route("/inventory/import-zip", methods=["POST"])
def import_zip():
    g = _guard()
    if g:
        return g
    a = actor()
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
        # VULN(zip-slip): entry names trusted during extraction.
        real = os.path.realpath(os.path.join(dest, name))
        if not real.startswith(os.path.realpath(dest)):
            engine.solve("zip-slip-import", a, {"entry": name, "resolved": real})
    return {"entries": z.namelist()}


@bp.route("/render")
def render_theme():
    g = _guard()
    if g:
        return g
    a = actor()
    theme = request.args.get("theme", "default")
    # VULN(file-inclusion-rce): theme name builds an include path (traversal).
    base = os.path.join(config.DATA_DIR, "themes")
    os.makedirs(base, exist_ok=True)
    path = os.path.normpath(os.path.join(base, theme + ".html"))
    if not os.path.realpath(path).startswith(os.path.realpath(base)):
        engine.solve("file-inclusion-rce", a, {"theme": theme, "resolved": path})
        try:
            return open(os.path.realpath(path)).read()
        except OSError:
            return {"included": theme}
    return {"theme": theme}


@bp.route("/prefs/import", methods=["POST"])
def prefs_import():
    g = _guard()
    if g:
        return g
    a = actor()
    blob = request.values.get("prefs") or request.cookies.get("prefs", "")
    try:
        raw = base64.b64decode(blob)
    except Exception:
        return {"error": "bad blob"}, 400
    # SINK detection: a pickle carrying a code-exec primitive is RCE on load.
    if dangerous_pickle(raw):
        engine.solve("python-pickle-rce", a, {"opcodes": "dangerous-global"})
    collab.arm_from_payload(raw.decode("latin1", "ignore"), "python-pickle-rce", a)
    try:
        pickle.loads(raw)  # noqa: S301  VULN(python-pickle-rce)
    except Exception:
        pass
    return {"ok": True}


# ---- integrations / reports / access-control -------------------------------

@bp.route("/integrations/webhook/test", methods=["POST"])
def webhook_test():
    g = _guard()
    if g:
        return g
    a = actor()
    url = request.form.get("url", "")
    # VULN(ssrf-blind): server issues the request; no body returned.
    _s, _b, meta = fetcher.fetch(url, finding_ctx=("ssrf-blind-webhook", a))
    if meta["reached"] in ("internal", "metadata", "collab"):
        engine.solve("ssrf-blind-webhook", a, {"url": url, "reached": meta["reached"]})
    return {"ok": True, "dispatched": True}


@bp.route("/integrations/fx-sync", methods=["POST"])
def fx_sync():
    g = _guard()
    if g:
        return g
    a = actor()
    upstream = request.form.get("upstream", "")
    # VULN(api-unsafe-consumption): trusts and fetches an operator-supplied upstream.
    _s, _b, meta = fetcher.fetch(upstream, finding_ctx=("api-unsafe-consumption", a))
    if meta["reached"] in ("internal", "metadata", "collab"):
        engine.solve("api-unsafe-consumption", a, {"upstream": upstream, "reached": meta["reached"]})
    return {"ok": True, "synced": True}


@bp.route("/reports/financials")
def reports_financials():
    # VULN(forced-browsing): unlinked, unauthenticated sensitive report.
    a = actor()
    rows = db.query("SELECT id,total,secret FROM orders")
    body = [dict(r) for r in rows]
    engine.leaked_canary("forced-browsing-reports", a, str(body))
    return {"report": "financials", "orders": body}


@bp.route("/public/<path:sub>")
def public_proxy(sub):
    # VULN(path-normalization-bypass): the allowlist matches the raw prefix, but an
    # encoded traversal segment reaches the admin console after normalization.
    a = actor()
    raw = request.full_path
    if "..%2f" in raw.lower() or "..%2F" in raw or "../" in sub:
        if "admin" in sub or "admin" in raw.lower():
            engine.leaked_canary("path-normalization-admin", a,
                                 "SPRKL-CANARY-ADMIN-CONSOLE admin console tokens")
            engine.solve("path-normalization-admin", a, {"raw": raw})
            return {"console": "admin", "secret": "SPRKL-CANARY-ADMIN-CONSOLE"}
    return {"public": sub}
