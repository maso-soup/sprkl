"""Retail (customer) tier: accounts, cart, checkout, files, sessions."""
import re, time, hashlib, sqlite3, os, subprocess, zipfile, io, base64, pickle, hmac
from flask import (Blueprint, request, render_template, session,
                   redirect, url_for, render_template_string)
from ... import db, config, tap
from ...util import actor

bp = Blueprint("retail", __name__, url_prefix="/retail")


def _md5(s):
    return hashlib.md5(s.encode()).hexdigest()


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        sql = ("SELECT id,email,pw_md5,name FROM users WHERE email='" + email +
               "' AND password='" + password + "'")
        try:
            rows = db.query(sql, None)
        except sqlite3.Error as e:
            rows, error = [], str(e)
        if rows:
            _login_fail[email] = 0
            row = rows[0]
            tap.emit("auth.result", mechanism="password", ok=True,
                     password_verified=(row["pw_md5"] == _md5(password)),
                     principal=f"user:{row['id']}", user=email,
                     session_rotated=False, consecutive_failures=0)
            session["uid"] = row["id"]
            session["uname"] = row["name"]
            resp = redirect(url_for("retail.dashboard"))
            if request.form.get("remember"):
                import base64 as _b64
                resp.set_cookie("remember", _b64.b64encode(f"{row['id']}:1".encode()).decode())
            return resp
        _login_fail[email] = _login_fail.get(email, 0) + 1
        tap.emit("auth.result", mechanism="password", ok=False,
                 password_verified=False, principal=None, user=email,
                 consecutive_failures=_login_fail[email], locked=False)
        error = error or "Invalid credentials"
    return render_template("retail_login.html", error=error)


@bp.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not (name and email and password):
            error = "Name, email, and password are all required."
        elif db.query("SELECT id FROM users WHERE email=?", (email,), one=True):
            error = "An account with that email already exists."
        else:
            secret = config.TOKEN_PREFIX + "USER-" + os.urandom(4).hex()
            uid = db.execute(
                "INSERT INTO users (email,password,pw_md5,name,role,loyalty,secret) "
                "VALUES (?,?,?,?,?,?,?)",
                (email, password, _md5(password), name, "customer", 0, secret))
            # Report the new row's marker so the scorer can attribute it; the app
            # still does not know what a marker is for.
            tap.emit("obj.assign", target="users.secret", uid=uid, value=secret,
                     principal=f"user:{uid}")
            db.execute("INSERT INTO wallet (user_id,balance) VALUES (?,0)", (uid,))
            db.execute("INSERT INTO referrals (code,owner_id,redeemed_by) VALUES (?,?,NULL)",
                       (f"REF-{uid}", uid))
            session["uid"] = uid
            session["uname"] = name
            return redirect(url_for("retail.dashboard"))
    return render_template("retail_register.html", error=error)


@bp.route("/account")
def account():
    if not session.get("uid"):
        return redirect(url_for("retail.login"))
    u = db.query("SELECT id,email,name,loyalty FROM users WHERE id=?",
                 (session["uid"],), one=True)
    return render_template("retail_account.html", u=u)


@bp.route("/track")
def track():
    ref = request.args.get("ref", "")
    order = None
    error = None
    if ref:
        sql = "SELECT id,status,ref FROM orders WHERE ref='" + ref + "'"
        try:
            rows = db.query(sql, None)
            order = rows[0] if rows else None
        except sqlite3.Error as e:
            error = str(e)
    return render_template("retail_track.html", ref=ref, order=order, error=error)


@bp.route("/cart/giftmessage", methods=["POST"])
def giftmessage():
    msg = request.form.get("message", "")
    rendered = render_template_string("Gift note: " + msg)
    tap.emit("tmpl.render", from_path=False, source=msg, result=rendered,
             engine="jinja2")
    return render_template("retail_gift.html", rendered=rendered, msg=msg)


@bp.route("/cart/apply-coupon", methods=["POST"])
def apply_coupon():
    code = request.form.get("code", "")
    subtotal = float(request.form.get("subtotal", "100") or 100)
    a = actor()
    c = db.query("SELECT code,kind,value,used FROM coupons WHERE code=?",
                 (code,), one=True)
    if not c:
        return {"ok": False, "error": "unknown coupon"}, 404

    discount = 0.0
    if c["kind"] == "percent":
        discount = subtotal * (float(c["value"]) / 100.0)
    elif c["kind"] == "formula":
        formula = request.form.get("formula", c["value"])
        tap.emit("code.eval", language="python", source=formula,
                 supplied_by_request="formula" in request.form)
        try:
            discount = float(eval(formula,  # noqa: S307
                                  {"subtotal": subtotal, "min": min, "max": max}))
        except Exception:
            discount = 0.0

    prior = db.query("SELECT COUNT(*) n FROM coupon_redemptions WHERE code=? AND actor=?",
                     (code, a), one=True)["n"]
    db.execute("INSERT INTO coupon_redemptions (code,actor) VALUES (?,?)", (code, a))
    tap.emit("coupon.redeem", code=code, kind=c["kind"], prior_redemptions=prior,
             single_use=(code == "ONCE20"))

    return {"ok": True, "discount": round(discount, 2),
            "total": round(subtotal - discount, 2)}


# ==========================================================================
# Business logic
# ==========================================================================
_giftcard_lock_free = True   # intentionally NOT a real lock (race window)


@bp.route("/cart/update", methods=["POST"])
def cart_update():
    a = actor()
    price = 3.50
    try:
        qty = float(request.form.get("qty", "1"))
    except ValueError:
        qty = 1.0
    subtotal = price * qty
    total = subtotal
    if qty >= 2**31:
        total = (int(subtotal * 100) & 0xFFFFFFFF) / 100.0
    tap.emit("order.total", qty=qty, unit_price=price, subtotal=subtotal,
             total=total)
    return {"qty": qty, "subtotal": round(subtotal, 2), "total": round(total, 2)}


@bp.route("/wallet/redeem", methods=["POST"])
def wallet_redeem():
    import time as _t
    a = actor()
    code = request.form.get("code", "")
    gc = db.query("SELECT id,balance FROM giftcards WHERE code=?", (code,), one=True)
    if not gc or gc["balance"] <= 0:
        return {"ok": False}, 400
    # check-then-debit, not atomic
    bal = gc["balance"]
    _t.sleep(0.15)
    db.execute("UPDATE giftcards SET balance=balance-? WHERE id=?", (bal, gc["id"]))
    db.execute("UPDATE wallet SET balance=balance+? WHERE user_id=?",
               (bal, request.form.get("uid", 1)))
    after = db.query("SELECT balance FROM giftcards WHERE id=?", (gc["id"],), one=True)["balance"]
    tap.emit("giftcard.redeem", code=code, balance_before=bal, balance_after=after,
             credited=bal, atomic=False)
    return {"ok": True, "credited": bal}


@bp.route("/checkout/<step>", methods=["POST"])
def checkout(step):
    a = actor()
    steps = session.setdefault("checkout_steps", [])
    if step == "pay":
        steps.append("pay")
        session.modified = True
        return {"ok": True, "paid": True}
    if step == "confirm":
        tap.emit("order.finalize", steps=list(steps),
                 required=["pay"], confirmed=True)
        return {"ok": True, "order": "confirmed"}
    return {"ok": True, "step": step}


@bp.route("/referral/redeem", methods=["POST"])
def referral_redeem():
    a = actor()
    code = request.form.get("code", "")
    ref = db.query("SELECT owner_id FROM referrals WHERE code=?", (code,), one=True)
    if not ref:
        return {"ok": False}, 404
    tap.emit("obj.assign", target="referrals.redeemed_by", code=code,
             owner_uid=ref["owner_id"], redeemer_uid=session.get("uid"),
             compared=False)
    db.execute("UPDATE referrals SET redeemed_by=? WHERE code=?", (a, code))
    return {"ok": True, "credit": 5}


_rl_hits = {}  # (session, ip) attempts


@bp.route("/cart/guess-coupon", methods=["POST"])
def guess_coupon():
    from ...util import client_ip
    a = actor()
    ip = client_ip()
    key = (a, ip)
    _rl_hits[key] = _rl_hits.get(key, 0) + 1
    ips_used = {k[1] for k in _rl_hits if k[0] == a}
    total_attempts = sum(v for k, v in _rl_hits.items() if k[0] == a)
    tap.emit("obj.assign", target="ratelimit", bucket_ip=ip,
             distinct_buckets=len(ips_used), attempts=total_attempts,
             limit=5, throttled=_rl_hits[key] > 5)
    if _rl_hits[key] > 5:
        return {"error": "rate limited"}, 429
    return {"ok": True}


# ==========================================================================
# Files & path
# ==========================================================================
INVOICE_DIR = os.path.join(config.DATA_DIR, "invoices")
UPLOAD_DIR = os.path.join(config.DATA_DIR, "uploads")


def _ensure_dirs():
    os.makedirs(INVOICE_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    inv = os.path.join(INVOICE_DIR, "INV-1001.txt")
    if not os.path.exists(inv):
        open(inv, "w").write("SPRKL invoice INV-1001 total $42.00")
    secret = os.path.join(config.DATA_DIR, "server-secret.txt")
    if not os.path.exists(secret):
        open(secret, "w").write(config.SPEC.get("assets", {}).get("server_file", ""))


@bp.route("/orders/<int:oid>/invoice")
def order_invoice(oid):
    a = actor()
    o = db.query("SELECT id,user_id,total,status,ref,secret FROM orders WHERE id=?", (oid,), one=True)
    if not o:
        return {"error": "not found"}, 404
    return {"invoice": f"INV-{oid}", "ref": o["ref"], "total": o["total"], "secret": o["secret"]}


@bp.route("/invoices/download")
def invoice_download():
    _ensure_dirs()
    a = actor()
    fname = request.args.get("file", "INV-1001.txt")
    path = os.path.join(INVOICE_DIR, fname)
    real = os.path.realpath(path)
    root = os.path.realpath(INVOICE_DIR)
    try:
        data = open(real).read()
    except OSError:
        data = None
    tap.emit("fs.read", requested=fname, resolved=real, root=root,
             bytes_read=len(data or ""), found=data is not None)
    if data is None:
        return {"error": "not found"}, 404
    return {"file": fname, "data": data}


@bp.route("/wishlist")
def wishlist():
    a = actor()
    uid = request.args.get("uid", type=int) or session.get("uid")
    rows = db.query("SELECT item,secret,user_id FROM wishlists WHERE user_id=?", (uid,))
    body = [dict(r) for r in rows]
    if request.args.get("format") == "json":
        return {"uid": uid, "items": body}
    return render_template("retail_wishlist.html", uid=uid, items=body)


@bp.route("/account/avatar", methods=["POST"])
def avatar_upload():
    _ensure_dirs()
    a = actor()
    f = request.files.get("file")
    ctype = request.form.get("content_type") or (f.content_type if f else "")
    fname = (f.filename if f else request.form.get("filename", "avatar.png"))
    data = f.read() if f else request.form.get("data", "").encode()
    tap.emit("obj.assign", target="uploads", filename=fname,
             declared_content_type=ctype, bytes_len=len(data),
             checked="content_type_only",
             extension=os.path.splitext(fname)[1].lower())
    expanded = ""
    if fname.lower().endswith(".svg") or b"<svg" in data[:200].lower():
        expanded = _parse_svg_xxe(data, a)
    if fname.lower().endswith((".html", ".j2", ".tpl")):
        save = os.path.join(UPLOAD_DIR, os.path.basename(fname))
        open(save, "wb").write(data)
    return {"ok": True, "stored": os.path.basename(fname), "preview": (expanded or "")[:200]}


def _parse_svg_xxe(data, a):
    """Resolve a SYSTEM file:// entity in an uploaded SVG and return its content
    (a rendered SVG would expose it), so the leak is observable in the response."""
    try:
        text = data.decode("utf-8", "ignore")
    except Exception:
        return ""
    m = re.search(r'<!ENTITY\s+\w+\s+SYSTEM\s+"file://([^"]+)"', text)
    if not m:
        return ""
    path = m.group(1)
    try:
        content = open(path).read()
    except OSError:
        content = ""
    tap.emit("xml.parse", external_entities=True, entity_uri=path,
             resolved=path, root="/", bytes_read=len(content), source="svg")
    return content


@bp.route("/uploads/<name>")
def serve_upload(name):
    _ensure_dirs()
    path = os.path.join(UPLOAD_DIR, os.path.basename(name))
    if not os.path.exists(path):
        return {"error": "not found"}, 404
    content = open(path).read()
    if name.lower().endswith((".html", ".j2", ".tpl")):
        rendered = render_template_string(content)
        tap.emit("tmpl.render", from_path=True, source=content, result=rendered,
                 engine="jinja2", stored_upload=True)
        return rendered
    return content


# ==========================================================================
# SSRF (avatar-from-url)
# ==========================================================================
@bp.route("/account/avatar-from-url", methods=["POST"])
def avatar_from_url():
    a = actor()
    url = request.form.get("url", "")
    from ...backends import fetcher
    status, body, meta = fetcher.fetch(url)
    return {"status": status, "reached": meta["reached"], "body": body}


# ==========================================================================
# Auth / session / reset
# ==========================================================================
@bp.route("/reset/request", methods=["POST"])
def reset_request():
    a = actor()
    email = request.form.get("email", "")
    minute = int(time.time() // 60)
    token = hashlib.md5(f"{email}:{minute}".encode()).hexdigest()
    host = request.headers.get("Host", "127.0.0.1")
    link = f"http://{host}/retail/reset?token={token}"
    tap.emit("token.issue", kind="password-reset", derived_from="email+minute",
             algorithm="md5", entropy_bits=0, link=link, host_from_header=True)
    session["_reset_token"] = token
    return {"ok": True, "sent": True, "link": link}


@bp.route("/reset")
def reset_do():
    a = actor()
    token = request.args.get("token", "")
    email = request.args.get("email", "")
    minute = int(time.time() // 60)
    for m in (minute, minute - 1):
        if token == hashlib.md5(f"{email}:{m}".encode()).hexdigest() and email:
            u = db.query("SELECT id FROM users WHERE email=?", (email,), one=True)
            tap.emit("auth.result", mechanism="reset-token", ok=True,
                     password_verified=False,
                     principal=f"user:{u['id']}" if u else None, user=email,
                     token_derived_from="email+minute")
            return {"ok": True, "reset_for": email}
    return {"ok": False}, 400


@bp.route("/login-fixation", methods=["POST"])
def login_fixation():
    """The caller may supply the session id; it is not regenerated on auth."""
    a = actor()
    sid = request.args.get("sid") or request.form.get("sid")
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    u = db.query("SELECT id,pw_md5 FROM users WHERE email=?", (email,), one=True)
    if u and u["pw_md5"] == _md5(password):
        if sid:
            session["sid"] = sid
            session["uid"] = u["id"]
        tap.emit("auth.result", mechanism="password", ok=True,
                 password_verified=True, principal=f"user:{u['id']}", user=email,
                 session_rotated=False, adopted_sid=sid)
        return {"ok": True}
    return {"ok": False}, 401


@bp.route("/whoami")
def whoami():
    a = actor()
    remember = request.cookies.get("remember", "")
    if remember:
        try:
            decoded = base64.b64decode(remember).decode()
            uid = int(decoded.split(":")[0])
        except Exception:
            return {"user": None}
        u = db.query("SELECT id,email FROM users WHERE id=?", (uid,), one=True)
        tap.emit("auth.result", mechanism="remember-cookie", ok=bool(u),
                 password_verified=False,
                 principal=f"user:{uid}" if u else None,
                 token_encoding="base64", token_signed=False)
        return {"user": u["email"] if u else None}
    return {"user": None}


_login_fail = {}


@bp.route("/api-login", methods=["POST"])
def api_login_retail():
    a = actor()
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    u = db.query("SELECT id,pw_md5 FROM users WHERE email=?", (email,), one=True)
    if u and u["pw_md5"] == _md5(password):
        _login_fail[email] = 0
        return {"ok": True}
    _login_fail[email] = _login_fail.get(email, 0) + 1
    tap.emit("auth.result", mechanism="password", ok=False,
             password_verified=False, principal=None, user=email,
             consecutive_failures=_login_fail[email], locked=False)
    return {"ok": False}, 401


@bp.route("/oauth/authorize")
def oauth_authorize():
    a = actor()
    redirect_uri = request.args.get("redirect_uri", "")
    return redirect(redirect_uri + ("&" if "?" in redirect_uri else "?") + "code=AUTHCODE123"
                    if redirect_uri else "/")


# ==========================================================================
# Crypto / data
# ==========================================================================
@bp.route("/profile/load")
def profile_load():
    a = actor()
    cookie = request.cookies.get("profile", "")
    if "." not in cookie:
        return {"ok": False}, 400
    data, mac = cookie.rsplit(".", 1)
    from ...util import weak_mac
    verified = weak_mac(data) == mac
    tap.emit("auth.result", mechanism="mac-cookie", ok=verified,
             password_verified=False, principal=None, data=data,
             mac_construction="md5(secret||data)")
    if verified:
        return {"ok": True, "data": data}
    return {"ok": False, "error": "bad mac"}, 400


_padding_probes = {}


@bp.route("/coupon/decrypt")
def coupon_decrypt():
    a = actor()
    enc = request.args.get("enc", "")
    _padding_probes.setdefault(a, set()).add(enc)
    ok = (len(enc) % 32 == 0) and enc[-2:] != "zz"
    return ({"padding": "valid"} if ok else ({"padding": "invalid"}, 400))


@bp.route("/promo/token")
def promo_token():
    import random
    rng = random.Random(config.WEAK_RNG_SEED + session.get("promo_n", 0))
    tok = rng.randint(100000, 999999)
    session["promo_n"] = session.get("promo_n", 0) + 1
    session["promo_expected"] = tok
    tap.emit("token.issue", kind="promo", source="seeded-prng",
             algorithm="Mersenne", entropy_bits=0)
    return {"token": tok}


@bp.route("/promo/claim")
def promo_claim():
    a = actor()
    import random
    tok = request.args.get("token", type=int)
    rng = random.Random(config.WEAK_RNG_SEED + session.get("promo_n", 0))
    expected = rng.randint(100000, 999999)
    tap.emit("token.issue", kind="promo-claim", source="seeded-prng",
             algorithm="Mersenne", entropy_bits=0, matched=(tok == expected),
             supplied=tok)
    if tok == expected:
        return {"ok": True}
    return {"ok": False}, 400


# ==========================================================================
# Client-side (retail)
# ==========================================================================
@bp.route("/products/<int:pid>/review", methods=["POST"])
def submit_review(pid):
    a = actor()
    body = request.form.get("body", "")
    author = session.get("uname", "guest")
    db.execute("INSERT INTO reviews (product_id,author,body) VALUES (?,?,?)",
               (pid, author, body))
    tap.emit("cache.store", store="reviews", field="body", value=body, pid=pid)
    return {"ok": True, "pid": pid}


@bp.route("/account/email", methods=["POST"])
def change_email():
    a = actor()
    if not session.get("uid"):
        return {"error": "auth required"}, 401
    new_email = request.form.get("email", "")
    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    ours = (f"http://127.0.0.1:{config.APP_PORT}", f"http://localhost:{config.APP_PORT}")
    cross_site = ((origin and not origin.startswith(ours)) or
                  (referer and not referer.startswith(ours)))
    db.execute("UPDATE users SET email=? WHERE id=?", (new_email, session["uid"]))
    tap.emit("obj.assign", target="users.email", uid=session["uid"],
             csrf_token_required=False,
             csrf_token_present=bool(request.form.get("csrf_token")),
             cross_site=bool(cross_site))
    return {"ok": True}


@bp.route("/wallet/transfer")
def wallet_transfer():
    return render_template("wallet_transfer.html")


@bp.route("/dashboard")
def dashboard():
    if not session.get("uid"):
        return redirect(url_for("retail.login"))
    u = db.query("SELECT id,name,email,loyalty FROM users WHERE id=?",
                 (session["uid"],), one=True)
    orders = db.query("SELECT id,total,status,ref FROM orders WHERE user_id=? ORDER BY id DESC",
                      (session["uid"],))
    recs = db.query("SELECT id,name,flavor,price FROM products WHERE listed=1 LIMIT 3")
    return render_template("retail_dashboard.html", u=u, orders=orders, recs=recs)


# ==========================================================================
# Account area GUI (each page is the natural entry point for its findings)
# ==========================================================================
def _require_login():
    return None if session.get("uid") else redirect(url_for("retail.login"))


@bp.route("/orders")
def orders():
    if not session.get("uid"):
        return redirect(url_for("retail.login"))
    rows = db.query("SELECT id,total,status,ref FROM orders WHERE user_id=? ORDER BY id DESC",
                    (session["uid"],))
    return render_template("retail_orders.html", orders=rows)


@bp.route("/giftcards")
def giftcards():
    if not session.get("uid"):
        return redirect(url_for("retail.login"))
    rows = db.query("SELECT id,code,balance FROM giftcards WHERE owner_id=?", (session["uid"],))
    return render_template("retail_giftcards.html", cards=rows)


@bp.route("/wallet")
def wallet():
    if not session.get("uid"):
        return redirect(url_for("retail.login"))
    w = db.query("SELECT balance FROM wallet WHERE user_id=?", (session["uid"],), one=True)
    return render_template("retail_wallet.html", balance=(w["balance"] if w else 0))


@bp.route("/referrals")
def referrals():
    if not session.get("uid"):
        return redirect(url_for("retail.login"))
    ref = db.query("SELECT code FROM referrals WHERE owner_id=?", (session["uid"],), one=True)
    return render_template("retail_referrals.html", code=(ref["code"] if ref else "REF-YOU"))


@bp.route("/profile")
def profile():
    if not session.get("uid"):
        return redirect(url_for("retail.login"))
    u = db.query("SELECT id,name,email,address FROM users WHERE id=?", (session["uid"],), one=True)
    return render_template("retail_profile.html", u=u)


@bp.route("/security")
def security():
    if not session.get("uid"):
        return redirect(url_for("retail.login"))
    return render_template("retail_security.html")


@bp.route("/orders/<int:oid>")
def order_detail(oid):
    if not session.get("uid"):
        return redirect(url_for("retail.login"))
    o = db.query("SELECT id,user_id,total,status,ref FROM orders WHERE id=?", (oid,), one=True)
    return render_template("retail_order_detail.html", o=o, oid=oid)
