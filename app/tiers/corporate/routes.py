"""Corporate / admin tier.

  - default-creds-admin (login infra; oracle wired in Phase C)
  - blind-command-injection : OAST-proven RCE in the connectivity tester
"""
from flask import Blueprint, request, render_template, session, redirect, url_for
import subprocess
from ...util import actor, dangerous_pickle
from ...oracle import engine, collab
from ... import config, db
from ...backends import nosql, ldap

bp = Blueprint("corporate", __name__, url_prefix="/corporate")


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        row = db.query("SELECT id,email,role FROM users WHERE email=? AND password=? "
                       "AND role IN ('admin','buyer')", (user, pw), one=True)
        # allow the classic default-cred shorthand too
        if not row and user == "admin" and pw == "admin":
            row = db.query("SELECT id,email,role FROM users WHERE role='admin'", one=True)
        if row:
            # VULN(default-creds-admin): admin/admin works out of the box.
            if user == "admin" and pw == "admin":
                engine.solve("default-creds-admin", actor(), {"username": user})
            session["corp"] = row["id"]
            session["corp_role"] = row["role"]
            return redirect(url_for("corporate.dashboard"))
        error = "Invalid corporate credentials"
    return render_template("corporate_login.html", error=error)


@bp.route("/dashboard")
def dashboard():
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
    return render_template("corporate_dashboard.html",
                           role=session.get("corp_role"))


@bp.route("/tools/ping", methods=["GET", "POST"])
def ping():
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
    host = request.values.get("host", "")
    output = ""
    if host:
        import re as _re
        a = actor()
        # VULN(blind-command-injection): host concatenated into a shell command.
        cmd = "ping -c 1 " + host
        # Oracle = SINK-side detection: the server itself runs the shell, so it can
        # observe that the host field injected an extra command (a shell control
        # operator followed by a token). This credits the finding no matter where
        # the tester's out-of-band callback goes -- a real tester uses THEIR OWN
        # collaborator, not our internal one.
        if _re.search(r'(;|\|\||&&|\||\$\(|`)\s*\S', host):
            engine.solve("blind-command-injection", a, {"host": host, "cmd": cmd})
        # Still ALSO credit an internal /collab callback, for tooling that uses it.
        collab.arm_from_payload(host, "blind-command-injection", a)
        try:
            subprocess.run(cmd, shell=True, timeout=8,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        output = "Connectivity check dispatched."  # blind: no command output shown
    return render_template("corporate_ping.html", host=host, output=output)


@bp.route("/api/login", methods=["POST"])
def api_login():
    """VULN(nosql-login-bypass): JSON login against the Mongo-style corp store;
    operator objects like {"$ne": null} are honored."""
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    docs = nosql.find("corp_users", {"username": username, "password": password})
    if docs:
        d = docs[0]
        # bypass = the supplied password is not a real string match
        if not isinstance(password, str) or d.get("password") != password:
            engine.solve("nosql-login-bypass", actor(),
                         {"username": username, "password": password})
        session["corp"] = d.get("username")
        session["corp_role"] = d.get("role")
        return {"ok": True, "role": d.get("role")}
    return {"ok": False}, 401


@bp.route("/labels/generate", methods=["POST"])
def labels_generate():
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
    filename = request.values.get("filename", "label")
    # VULN(os-command-injection): filename concatenated into a shell command.
    out = subprocess.run("echo LABEL:" + filename, shell=True,
                         capture_output=True, text=True, timeout=8).stdout
    # Oracle: injected command produced output beyond the label text.
    marker_lines = [l for l in out.splitlines() if l and not l.startswith("LABEL:")]
    if any(c in filename for c in [";", "|", "&", "$(", "`"]) and marker_lines:
        engine.solve("os-command-injection", actor(),
                     {"filename": filename, "extra_output": marker_lines[:3]})
    return {"output": out}


@bp.route("/directory")
def directory():
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
    u = request.args.get("u", "")
    # VULN(ldap-injection): filter built by concatenation.
    flt = "(uid=" + u + ")"
    results = ldap.search(flt)
    engine.leaked_canary("ldap-injection", actor(), str(results))
    return {"filter": flt, "results": results}


# ==========================================================================
# Deserialization / files / SSRF / access-control (corporate)
# ==========================================================================
import os, io, zipfile, base64, pickle, time as _time
import xml.sax
from xml.dom import minidom
from ... import config
from ...backends import fetcher


@bp.route("/inventory/import", methods=["POST"])
def inventory_import():
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
    a = actor()
    xml_data = request.get_data(as_text=True)
    # VULN(xxe-xml-import): external entities enabled; SYSTEM file:// entities resolved.
    import re as _re
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
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
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
        target = os.path.join(dest, name)
        real = os.path.realpath(target)
        if not real.startswith(os.path.realpath(dest)):
            engine.solve("zip-slip-import", a, {"entry": name, "resolved": real})
    return {"entries": z.namelist()}


@bp.route("/render")
def render_theme():
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
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
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
    a = actor()
    blob = request.values.get("prefs") or request.cookies.get("prefs", "")
    from ...oracle import collab
    try:
        raw = base64.b64decode(blob)
    except Exception:
        return {"error": "bad blob"}, 400
    # SINK detection: a pickle carrying a code-exec primitive is RCE on load,
    # regardless of what the gadget calls out to.
    if dangerous_pickle(raw):
        engine.solve("python-pickle-rce", a, {"opcodes": "dangerous-global"})
    collab.arm_from_payload(raw.decode("latin1", "ignore"), "python-pickle-rce", a)
    try:
        # VULN(python-pickle-rce): untrusted pickle deserialized.
        pickle.loads(raw)  # noqa: S301
    except Exception:
        pass
    return {"ok": True}


@bp.route("/tools/mfa-skip")
def mfa_skip():
    # VULN(mfa-bypass): the dashboard trusts a pre-MFA session state.
    a = actor()
    if session.get("pre_mfa") and not session.get("mfa_done"):
        session["corp"] = session.get("pre_mfa")
        session["corp_role"] = "admin"
        engine.solve("mfa-bypass-skip-step", a, {"skipped": True})
        return {"ok": True, "dashboard": "granted"}
    return {"ok": False}, 403


@bp.route("/mfa/begin", methods=["POST"])
def mfa_begin():
    # legitimate step 1: sets a pre-MFA marker meant only for the OTP page
    u = db.query("SELECT id FROM users WHERE role='admin'", one=True)
    session["pre_mfa"] = u["id"]
    return {"ok": True, "next": "/corporate/tools/mfa-skip (should require OTP)"}


@bp.route("/integrations/webhook/test", methods=["POST"])
def webhook_test():
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
    a = actor()
    url = request.form.get("url", "")
    # VULN(ssrf-blind): server issues the request; no body returned.
    _s, _b, meta = fetcher.fetch(url, finding_ctx=("ssrf-blind-webhook", a))
    # SINK detection: the server made a server-side request to an internal target,
    # regardless of any external collaborator the tester used.
    if meta["reached"] in ("internal", "metadata", "collab"):
        engine.solve("ssrf-blind-webhook", a, {"url": url, "reached": meta["reached"]})
    return {"ok": True, "dispatched": True}


@bp.route("/integrations/fx-sync", methods=["POST"])
def fx_sync():
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
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
def corp_public(sub):
    # VULN(path-normalization-bypass): allowlist matches the raw prefix, but an
    # encoded traversal segment reaches the admin console after normalization.
    a = actor()
    raw = request.full_path
    if "..%2f" in raw.lower() or "..%2F" in raw or "../" in sub:
        if "admin" in sub or "admin" in raw.lower():
            engine.leaked_canary("path-normalization-admin", a,
                                 "SPRKL-CANARY-CORP-ADMIN admin console tokens")
            engine.solve("path-normalization-admin", a, {"raw": raw})
            return {"console": "admin", "secret": "SPRKL-CANARY-CORP-ADMIN"}
    return {"public": sub}


@bp.route("/support/inbox")
def support_inbox():
    if not session.get("corp"):
        return redirect(url_for("corporate.login"))
    # VULN(blind-xss): stored contact messages rendered raw to staff.
    msgs = db.query("SELECT email,subject,message FROM contacts ORDER BY id DESC")
    return render_template("corporate_inbox.html", msgs=msgs)
