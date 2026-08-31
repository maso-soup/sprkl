"""Public (unauthenticated) storefront: home, search, catalog, product specs."""
import sqlite3
import xml.etree.ElementTree as ET
from flask import Blueprint, request, render_template, redirect, make_response, url_for
from markupsafe import Markup
from ... import db, tap
from ...util import actor
from ...backends import smtp

bp = Blueprint("public", __name__)


@bp.route("/")
def home():
    products = db.query("SELECT id,slug,name,flavor,price FROM products WHERE listed=1")
    return render_template("home.html", products=products)


@bp.route("/search")
def search():
    q = request.args.get("q", "")
    rows, error = [], None
    if q:
        sql = ("SELECT id,name,flavor,price FROM products "
               "WHERE name LIKE '%" + q + "%' OR flavor LIKE '%" + q + "%'")
        try:
            rows = db.query(sql, None)
        except sqlite3.Error as e:
            error = str(e)
    return render_template("search.html", q=q, rows=rows, error=error,
                           hl=request.args.get("hl", ""), reflected=Markup(q))


@bp.route("/products")
def products():
    category = request.args.get("category", "")
    in_stock = request.args.get("in_stock", "")
    sort = request.args.get("sort", "name")

    where = "listed=1"
    if category:
        where += " AND flavor='" + category + "'"
    if in_stock:
        where += " AND in_stock=" + in_stock
    sql = f"SELECT id,name,flavor,price FROM products WHERE {where} ORDER BY {sort}"
    rows, error = [], None
    try:
        rows = db.query(sql, None)
    except sqlite3.Error as e:
        error = str(e)

    flavors = [r["flavor"] for r in db.query("SELECT DISTINCT flavor FROM products WHERE listed=1")]
    return render_template("products.html", rows=rows, error=error, flavors=flavors,
                           category=category, in_stock=in_stock, sort=sort)


@bp.route("/products/<int:pid>/spec")
def product_spec(pid):
    field = request.args.get("field", "flavor")
    row = db.query("SELECT spec_xml FROM products WHERE id=?", (pid,), one=True)
    if not row:
        return {"error": "not found"}, 404
    try:
        root = ET.fromstring(row["spec_xml"])
    except ET.ParseError:
        return {"error": "bad spec"}, 500
    expr = ".//" + field
    try:
        nodes = root.findall(expr)
    except SyntaxError:
        nodes = []
    vals = [n.text for n in nodes if n is not None and n.text]
    tap.emit("xpath.eval", expr=expr, field=field, matches=len(vals))
    return {"field": field, "values": vals}


@bp.route("/go/track")
def go_track():
    nxt = request.args.get("next", "/")
    resp = make_response(redirect("/"))
    tap.emit("obj.assign", target="response.header", name="X-Sprkl-Next", value=nxt)
    try:
        resp.headers["X-Sprkl-Next"] = nxt
    except Exception:
        pass
    return resp


@bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        email = request.form.get("email", "")
        subject = request.form.get("subject", "")
        message = request.form.get("message", "")
        a = actor()
        extra = ""
        if "\n" in email or "\r" in email:
            extra = email.split("\n", 1)[1].replace("\r", "")
        msg = smtp.send("support@sprkl.example", subject, message, extra_headers=extra)
        tap.emit("mail.send", to="support@sprkl.example", subject=subject,
                 headers=list(msg["headers"]), extra=extra)
        db.execute("INSERT INTO contacts (email,subject,message,actor) VALUES (?,?,?,?)",
                   (email, subject, message, a))
        tap.emit("cache.store", store="contacts", field="message", value=message)
        return render_template("contact.html", sent=True)
    return render_template("contact.html", sent=False)


@bp.route("/product/<int:pid>")
def product_detail(pid):
    a = actor()
    p = db.query("SELECT id,name,flavor,price FROM products WHERE id=?", (pid,), one=True)
    if not p:
        return {"error": "not found"}, 404
    reviews = db.query("SELECT author,body FROM reviews WHERE product_id=?", (pid,))
    return render_template("product_detail.html", p=p, reviews=reviews)


@bp.route("/ref-landing")
def ref_landing():
    ref = request.args.get("ref", "")
    return render_template("ref_landing.html", ref=ref)


# ==========================================================================
# Storefront shell: cart, content pages (Phase 1 foundation)
# ==========================================================================
from ... import cart as cartmod


@bp.route("/cart")
def cart_page():
    lines, subtotal = cartmod.lines()
    return render_template("cart.html", lines=lines, subtotal=subtotal)


@bp.route("/cart/add", methods=["POST"])
def cart_add():
    try:
        pid = int(request.form.get("pid", 0))
        qty = int(request.form.get("qty", 1))
    except ValueError:
        return {"ok": False}, 400
    cartmod.add(pid, max(1, qty))
    return {"ok": True, "count": sum(i["qty"] for i in cartmod._cart())}


@bp.route("/cart/remove", methods=["POST"])
def cart_remove():
    try:
        cartmod.remove(int(request.form.get("pid", 0)))
    except ValueError:
        pass
    return redirect(url_for("public.cart_page"))


@bp.route("/about")
def about():
    return render_template("content.html", title="About SPRKL",
                           body="SPRKL is a small-batch sparkling water company. " )


@bp.route("/press")
def press():
    return render_template("content.html", title="Press",
                           body="For media inquiries, contact press@sprkl.example.")


@bp.route("/support")
def support():
    return render_template("contact.html", sent=False)


STORES = [
    {"name": "SPRKL Flagship — Downtown", "addr": "12 Fizz Lane", "city": "San Francisco", "zip": "94103", "hours": "9am–9pm", "miles": 0.4, "x": 28, "y": 42},
    {"name": "SPRKL Market — Mission", "addr": "9 Seltzer St", "city": "San Francisco", "zip": "94110", "hours": "8am–10pm", "miles": 1.2, "x": 52, "y": 60},
    {"name": "SPRKL Corner — SoMa", "addr": "1 Bubbly Blvd", "city": "San Francisco", "zip": "94107", "hours": "7am–11pm", "miles": 1.9, "x": 68, "y": 34},
    {"name": "SPRKL Depot — Oakland", "addr": "5 Carbonation Ct", "city": "Oakland", "zip": "94607", "hours": "9am–8pm", "miles": 6.3, "x": 42, "y": 72},
    {"name": "SPRKL Kiosk — Berkeley", "addr": "3 Effervescence Ave", "city": "Berkeley", "zip": "94704", "hours": "10am–7pm", "miles": 9.1, "x": 80, "y": 20},
]


@bp.route("/store-locator")
def store_locator():
    near = request.args.get("near", "")
    q = near.strip().lower()
    stores = [s for s in STORES if not q or q in s["city"].lower() or q in s["zip"]]
    return render_template("store_locator.html", stores=stores, near=near)


@bp.route("/newsletter", methods=["POST"])
def newsletter_signup():
    # benign signup; the vulnerable subscriber *lookup* is /api/v2/newsletter/find
    return render_template("content.html", title="Subscribed",
                           body="Thanks for subscribing to the SPRKL newsletter!")


@bp.route("/checkout")
def checkout_page():
    lines, subtotal = cartmod.lines()
    return render_template("checkout.html", lines=lines, subtotal=subtotal)


@bp.route("/newsletter/manage")
def newsletter_manage():
    return render_template("newsletter_manage.html")
