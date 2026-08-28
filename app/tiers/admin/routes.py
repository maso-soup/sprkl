"""Hidden admin console GUI (unlinked, unhinted — reached only by browsing to /admin).

These routes render the console chrome + forms; the forms post to the EXISTING
/corporate/* and /api/v2/admin/* endpoints, which are the unchanged vuln sinks.
"""
from flask import Blueprint, render_template, session, redirect, request
from ... import db

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _guard():
    return None if session.get("corp") else redirect("/admin")


@bp.route("")
@bp.route("/")
def login():
    if session.get("corp"):
        return redirect("/admin/console")
    return render_template("admin_login.html", error=None)


@bp.route("/console")
def console():
    g = _guard()
    if g:
        return g
    return render_template("admin_console.html", role=session.get("corp_role"))


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
    return render_template("admin_directory.html")


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
