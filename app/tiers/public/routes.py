"""Public (unauthenticated) storefront: home, search, catalog, product specs.

Injection sinks live here:
  - sqli-error-search   : error-based SQLi in /search
  - sqli-union-products : UNION SQLi (canary leak) in /products
  - sqli-blind-boolean  : blind extraction against the secret column in /products
"""
import re, sqlite3
import xml.etree.ElementTree as ET
from flask import Blueprint, request, render_template, redirect, make_response
from markupsafe import Markup
from ... import db
from ...util import actor, looks_xss, looks_mutation_xss, looks_dangling_markup
from ...oracle import engine
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
        # VULN(sqli-error-search): query built by string concatenation.
        sql = ("SELECT id,name,flavor,price FROM products "
               "WHERE name LIKE '%" + q + "%' OR flavor LIKE '%" + q + "%'")
        try:
            rows = db.raw_query(sql)
            # canary can also surface here via UNION -> treat as union finding
            engine.leaked_canary("sqli-union-products", actor(),
                                 " ".join(str(tuple(r)) for r in rows))
        except sqlite3.Error as e:
            error = str(e)  # reflected DB error
            if "'" in q or '"' in q:
                engine.solve("sqli-error-search", actor(),
                             {"q": q, "error": error, "sql": sql})
    # VULN(reflected-xss-search): q echoed unescaped into HTML.
    if re.search(r"<script|onerror=|onload=|<img|<svg|javascript:", q, re.I):
        engine.solve("reflected-xss-search", actor(), {"q": q})
    # DOM-XSS lives on a distinct 'hl' (highlight) param that a client script
    # writes into innerHTML. SINK: server sees the payload reach that param.
    hl = request.args.get("hl", "")
    if looks_xss(hl):
        engine.solve("dom-xss-search", actor(), {"hl": hl[:120]})
    from ...oracle import collab
    collab.arm_from_payload(hl, "dom-xss-search", actor())
    return render_template("search.html", q=q, rows=rows, error=error,
                           reflected=Markup(q))


@bp.route("/products")
def products():
    category = request.args.get("category", "")
    in_stock = request.args.get("in_stock", "")
    sort = request.args.get("sort", "name")

    where = "listed=1"
    if category:
        where += " AND flavor='" + category + "'"        # VULN: union sink
    if in_stock:
        where += " AND in_stock=" + in_stock             # VULN: blind sink
    # VULN(sqli-union-products / sqli-blind-boolean): fully string-built query
    sql = f"SELECT id,name,flavor,price FROM products WHERE {where} ORDER BY {sort}"
    rows, error = [], None
    try:
        rows = db.raw_query(sql)
    except sqlite3.Error as e:
        error = str(e)

    a = actor()
    # union canary: a planted secret appeared in output for a public actor
    engine.leaked_canary("sqli-union-products", a,
                         " ".join(str(tuple(r)) for r in rows))
    # blind boolean: genuine char-by-char extraction against the secret column
    raw = category + " " + in_stock
    if re.search(r"secret", raw, re.I) and re.search(r"(substr|like|=|<|>|glob)", raw, re.I):
        engine.solve("sqli-blind-boolean", a, {"probe": raw, "sql": sql})

    return render_template("products.html", rows=rows, error=error,
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
    # VULN(xpath-injection): field selector used to build an XPath expression.
    try:
        nodes = root.findall(".//" + field)
    except SyntaxError:
        nodes = []
    vals = [n.text for n in nodes if n is not None and n.text]
    engine.leaked_canary("xpath-injection", actor(), str(vals))
    return {"field": field, "values": vals}


@bp.route("/go/track")
def go_track():
    nxt = request.args.get("next", "/")
    resp = make_response(redirect("/"))
    # VULN(crlf-header-injection): value copied into a header verbatim.
    try:
        resp.headers["X-Sprkl-Next"] = nxt
    except Exception:
        pass
    # Werkzeug may sanitize; detect the raw CRLF+header attempt as the exploit.
    if ("\r" in nxt or "\n" in nxt or "%0d" in nxt.lower() or "%0a" in nxt.lower()) and ":" in nxt:
        engine.solve("crlf-header-injection", actor(), {"next": nxt})
    return resp


@bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        email = request.form.get("email", "")
        subject = request.form.get("subject", "")
        message = request.form.get("message", "")
        a = actor()
        # VULN(smtp-header-injection): extra header block built from user fields.
        extra = ""
        if "\n" in email or "\r" in email:
            extra = email.split("\n", 1)[1].replace("\r", "")
        msg = smtp.send("support@sprkl.example", subject, message, extra_headers=extra)
        if any(h.lower() in (k.lower() for k in msg["headers"]) for h in ["bcc", "cc"]):
            engine.solve("smtp-header-injection", a, {"headers": list(msg["headers"])})
        # store for the corporate support inbox (blind-xss landing)
        db.execute("INSERT INTO contacts (email,subject,message,actor) VALUES (?,?,?,?)",
                   (email, subject, message, a))
        # SINK: a script payload stored in a field that later renders raw to staff.
        if looks_xss(message):
            engine.solve("blind-xss-contact", a, {"stored_in": "support-inbox"})
        from ...oracle import collab
        collab.arm_from_payload(message, "blind-xss-contact", a)
        return render_template("contact.html", sent=True)
    return render_template("contact.html", sent=False)


@bp.route("/product/<int:pid>")
def product_detail(pid):
    a = actor()
    p = db.query("SELECT id,name,flavor,price FROM products WHERE id=?", (pid,), one=True)
    if not p:
        return {"error": "not found"}, 404
    reviews = db.query("SELECT author,body FROM reviews WHERE product_id=?", (pid,))
    from ...oracle import collab
    for r in reviews:
        body = r["body"] or ""
        # SINK: review bodies are served raw to every viewer.
        if looks_mutation_xss(body):
            engine.solve("mutation-xss", a, {"pid": pid})
        elif looks_dangling_markup(body):
            engine.solve("dangling-markup-exfil", a, {"pid": pid})
        elif looks_xss(body):
            engine.solve("stored-xss-review", a, {"pid": pid, "author": r["author"]})
        collab.arm_from_payload(body, "mutation-xss", a)
    return render_template("product_detail.html", p=p, reviews=reviews)


@bp.route("/ref-landing")
def ref_landing():
    a = actor()
    ref = request.args.get("ref", "")
    # SINK: {{ }} in ref reaches a client-side template evaluator.
    if "{{" in ref and "}}" in ref:
        engine.solve("csti", a, {"ref": ref[:120]})
    from ...oracle import collab
    collab.arm_from_payload(ref, "csti", a)
    return render_template("ref_landing.html", ref=ref)
