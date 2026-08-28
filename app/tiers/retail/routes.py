"""Retail (customer) tier.

Injection sinks:
  - sqli-login-bypass      : auth bypass via string-built login query
  - sqli-time-based        : time-based blind in order tracking
  - ssti-jinja-giftmessage : Jinja SSTI in gift message
  - code-injection-coupon  : eval() on formula coupons
Business-logic (state-diff):
  - coupon-reuse           : single-use coupon reused
"""
import re, time, hashlib, sqlite3, os, subprocess, zipfile, io, base64, pickle, hmac
from flask import (Blueprint, request, render_template, session,
                   redirect, url_for, render_template_string)
from ... import db, config
from ...util import actor
from ...oracle import engine

bp = Blueprint("retail", __name__, url_prefix="/retail")


def _md5(s):
    return hashlib.md5(s.encode()).hexdigest()


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        # VULN(sqli-login-bypass): query built from raw email.
        sql = ("SELECT id,email,pw_md5,name FROM users WHERE email='" + email +
               "' AND password='" + password + "'")
        try:
            rows = db.raw_query(sql)
        except sqlite3.Error as e:
            rows, error = [], str(e)
        if rows:
            _login_fail[email] = 0
            row = rows[0]
            # Oracle: authenticated, but the supplied password does NOT actually
            # match this row -> the match was achieved by injection, not creds.
            legit = (row["pw_md5"] == _md5(password))
            if not legit:
                engine.solve("sqli-login-bypass", actor(),
                             {"email": email, "matched_user": row["email"]})
            session["uid"] = row["id"]
            session["uname"] = row["name"]
            resp = redirect(url_for("retail.dashboard"))
            if request.form.get("remember"):
                # VULN(weak-session-token): remember cookie = base64(uid:counter)
                import base64 as _b64
                resp.set_cookie("remember", _b64.b64encode(f"{row['id']}:1".encode()).decode())
            return resp
        # VULN(credential-stuffing-no-lockout): failures are never rate-limited.
        _login_fail[email] = _login_fail.get(email, 0) + 1
        if _login_fail[email] >= 6:
            engine.solve("credential-stuffing-no-lockout", actor(),
                         {"email": email, "attempts": _login_fail[email]})
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
            secret = "SPRKL-CANARY-USER-" + os.urandom(4).hex()
            uid = db.execute(
                "INSERT INTO users (email,password,pw_md5,name,role,loyalty,secret) "
                "VALUES (?,?,?,?,?,?,?)",
                (email, password, _md5(password), name, "customer", 0, secret))
            # keep the (deliberately weak) canary model consistent for new accounts
            engine.register_canary(secret, owner=f"user:{uid}", kind="user-secret")
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
        # VULN(sqli-time-based): string-built; conn has a real sleep() function.
        sql = "SELECT id,status,ref FROM orders WHERE ref='" + ref + "'"
        t0 = time.time()
        try:
            rows = db.raw_query(sql)
            order = rows[0] if rows else None
        except sqlite3.Error as e:
            error = str(e)
        elapsed = time.time() - t0
        if "sleep" in ref.lower() and elapsed > 1.5:
            engine.solve("sqli-time-based", actor(),
                         {"ref": ref, "elapsed": round(elapsed, 2)})
    return render_template("retail_track.html", ref=ref, order=order, error=error)


@bp.route("/cart/giftmessage", methods=["POST"])
def giftmessage():
    msg = request.form.get("message", "")
    # VULN(ssti-jinja-giftmessage): user text rendered as a Jinja template.
    rendered = render_template_string("Gift note: " + msg)
    # Oracle: template evaluated -> output diverged from the literal input.
    if "{{" in msg and "}}" in msg and ("{{" not in rendered):
        engine.solve("ssti-jinja-giftmessage", actor(),
                     {"message": msg, "rendered": rendered[:200]})
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
        formula = request.form.get("formula", c["value"])  # attacker-controllable
        # VULN(code-injection-coupon): formula evaluated as Python (permissive).
        try:
            discount = float(eval(formula,  # noqa: S307
                                  {"subtotal": subtotal, "min": min, "max": max}))
        except Exception:
            discount = 0.0
        if re.search(r"(__|import|class|os\.|subprocess|open\(|globals|builtins)", formula):
            engine.solve("code-injection-coupon", a, {"formula": formula[:200]})

    # VULN(coupon-reuse): "single-use" ONCE20 is not enforced atomically.
    prior = db.query("SELECT COUNT(*) n FROM coupon_redemptions WHERE code=? AND actor=?",
                     (code, a), one=True)["n"]
    db.execute("INSERT INTO coupon_redemptions (code,actor) VALUES (?,?)", (code, a))
    if code == "ONCE20" and prior >= 1:
        # invariant violated: a one-time coupon redeemed more than once by one actor
        engine.solve("coupon-reuse", a, {"code": code, "redemptions": prior + 1})

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
    # VULN(price-tampering-negative): quantity may be negative -> credit.
    if qty < 0 and subtotal < 0:
        engine.solve("price-tampering-negative", a, {"qty": qty, "subtotal": subtotal})
    # VULN(integer-overflow-total): huge qty overflows a 32-bit total to garbage.
    if qty >= 2**31:
        wrapped = (int(subtotal * 100) & 0xFFFFFFFF) / 100.0
        engine.solve("integer-overflow-total", a, {"qty": qty, "wrapped_total": wrapped})
    return {"qty": qty, "subtotal": round(subtotal, 2)}


@bp.route("/wallet/redeem", methods=["POST"])
def wallet_redeem():
    import time as _t
    a = actor()
    code = request.form.get("code", "")
    gc = db.query("SELECT id,balance FROM giftcards WHERE code=?", (code,), one=True)
    if not gc or gc["balance"] <= 0:
        return {"ok": False}, 400
    # VULN(race-conditions): check-then-debit is not atomic (widened window).
    bal = gc["balance"]
    _t.sleep(0.15)
    db.execute("UPDATE giftcards SET balance=balance-? WHERE id=?", (bal, gc["id"]))
    db.execute("UPDATE wallet SET balance=balance+? WHERE user_id=?",
               (bal, request.form.get("uid", 1)))
    redeemed = db.query("SELECT balance FROM giftcards WHERE id=?", (gc["id"],), one=True)["balance"]
    if redeemed < 0:  # spent more than existed -> double spend happened
        engine.solve("race-giftcard-double-spend", a, {"code": code, "balance": redeemed})
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
        # VULN(workflow-bypass): confirm never verifies the pay step ran.
        if "pay" not in steps:
            engine.solve("workflow-bypass-payment", a, {"steps": steps})
        return {"ok": True, "order": "confirmed"}
    return {"ok": True, "step": step}


@bp.route("/referral/redeem", methods=["POST"])
def referral_redeem():
    a = actor()
    code = request.form.get("code", "")
    ref = db.query("SELECT owner_id FROM referrals WHERE code=?", (code,), one=True)
    if not ref:
        return {"ok": False}, 404
    # VULN(coupon-referral-abuse): referrer and referee are never compared.
    if session.get("uid") == ref["owner_id"]:
        engine.solve("referral-self-credit", a, {"code": code, "uid": session.get("uid")})
    db.execute("UPDATE referrals SET redeemed_by=? WHERE code=?", (a, code))
    return {"ok": True, "credit": 5}


_rl_hits = {}  # (session, ip) attempts


@bp.route("/cart/guess-coupon", methods=["POST"])
def guess_coupon():
    from ...util import client_ip
    a = actor()
    ip = client_ip()  # VULN: keyed on spoofable X-Forwarded-For
    key = (a, ip)
    _rl_hits[key] = _rl_hits.get(key, 0) + 1
    if _rl_hits[key] > 5:
        return {"error": "rate limited"}, 429
    # VULN(rate-limit-bypass): rotating X-Forwarded-For yields fresh buckets.
    ips_used = {k[1] for k in _rl_hits if k[0] == a}
    total_attempts = sum(v for k, v in _rl_hits.items() if k[0] == a)
    if len(ips_used) >= 5 and total_attempts > 10:
        engine.solve("rate-limit-bypass", a, {"distinct_ips": len(ips_used),
                                              "attempts": total_attempts})
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
        open(secret, "w").write("SPRKL-CANARY-SERVER-FILE")
        engine.register_canary("SPRKL-CANARY-SERVER-FILE", owner="system", kind="server-file")


@bp.route("/orders/<int:oid>/invoice")
def order_invoice(oid):
    a = actor()
    o = db.query("SELECT id,user_id,total,status,ref,secret FROM orders WHERE id=?", (oid,), one=True)
    if not o:
        return {"error": "not found"}, 404
    # VULN(idor-order-invoice): no ownership check.
    if a != f"user:{o['user_id']}":
        engine.leaked_canary("idor-order-invoice", a, str(dict(o)))
    return {"invoice": f"INV-{oid}", "ref": o["ref"], "total": o["total"], "secret": o["secret"]}


@bp.route("/invoices/download")
def invoice_download():
    _ensure_dirs()
    a = actor()
    fname = request.args.get("file", "INV-1001.txt")
    # VULN(path-traversal): file joined without normalization/containment.
    path = os.path.join(INVOICE_DIR, fname)
    real = os.path.realpath(path)
    if not real.startswith(os.path.realpath(INVOICE_DIR)):
        # traversal escaped the invoice dir
        try:
            data = open(real).read()
        except OSError:
            data = ""
        engine.solve("path-traversal-invoice", a, {"file": fname, "resolved": real})
        engine.leaked_canary("path-traversal-invoice", a, data)
        return {"file": fname, "data": data}
    try:
        return {"file": fname, "data": open(real).read()}
    except OSError:
        return {"error": "not found"}, 404


@bp.route("/wishlist")
def wishlist():
    a = actor()
    uid = request.args.get("uid", type=int) or session.get("uid")
    rows = db.query("SELECT item,secret,user_id FROM wishlists WHERE user_id=?", (uid,))
    body = [dict(r) for r in rows]
    # VULN(idor-wishlist): uid param overrides the session user.
    if uid is not None and a != f"user:{uid}":
        engine.leaked_canary("idor-wishlist", a, str(body))
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
    # VULN(unrestricted-upload-type): only the declared content-type is checked.
    if ctype.startswith("image/") and not fname.lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
        engine.solve("unrestricted-upload-type", a, {"filename": fname, "content_type": ctype})
    # VULN(xxe-svg-upload): SVG parsed as XML with entities enabled.
    if fname.lower().endswith(".svg") or b"<svg" in data[:200].lower():
        _parse_svg_xxe(data, a)
    # VULN(file-upload-webshell): server-side template kept + rendered on access.
    if fname.lower().endswith((".html", ".j2", ".tpl")):
        save = os.path.join(UPLOAD_DIR, os.path.basename(fname))
        open(save, "wb").write(data)
    return {"ok": True, "stored": os.path.basename(fname)}


def _parse_svg_xxe(data, a):
    import xml.sax
    try:
        text = data.decode("utf-8", "ignore")
    except Exception:
        return
    # naive entity expansion: resolve SYSTEM "file://..." entities
    m = re.search(r'<!ENTITY\s+\w+\s+SYSTEM\s+"file://([^"]+)"', text)
    if m:
        path = m.group(1)
        try:
            content = open(path).read()
        except OSError:
            content = ""
        engine.leaked_canary("xxe-svg-upload", a, content)


@bp.route("/uploads/<name>")
def serve_upload(name):
    _ensure_dirs()
    path = os.path.join(UPLOAD_DIR, os.path.basename(name))
    if not os.path.exists(path):
        return {"error": "not found"}, 404
    # VULN(file-upload-webshell): uploaded template rendered server-side.
    content = open(path).read()
    if name.lower().endswith((".html", ".j2", ".tpl")):
        rendered = render_template_string(content)
        if "{{" in content and rendered != content:
            engine.solve("file-upload-webshell", actor(), {"file": name, "rendered": rendered[:120]})
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
    status, body, meta = fetcher.fetch(url, finding_ctx=("ssrf-basic", a))
    if meta["reached"] == "collab":
        pass  # ssrf-basic solved via collab in fetcher
    elif meta["reached"] == "metadata":
        engine.leaked_canary("ssrf-cloud-metadata", a, body)
        # if a naive blocklist would have blocked "localhost/127.0.0.1" but this
        # host reached metadata via an alternate encoding, it's a filter bypass too
        if url and not any(x in url for x in ("169.254.169.254",)):
            engine.solve("ssrf-filter-bypass", a, {"url": url})
        else:
            engine.solve("ssrf-cloud-metadata", a, {"url": url})
    elif meta["reached"] == "internal":
        engine.solve("ssrf-basic", a, {"url": url, "reached": "internal"})
    return {"status": status, "reached": meta["reached"]}


# ==========================================================================
# Auth / session / reset
# ==========================================================================
@bp.route("/reset/request", methods=["POST"])
def reset_request():
    a = actor()
    email = request.form.get("email", "")
    # VULN(weak-randomness/predictable): token = md5(email + coarse minute)
    minute = int(time.time() // 60)
    token = hashlib.md5(f"{email}:{minute}".encode()).hexdigest()
    # VULN(host-header-attacks): reset link built from the Host header.
    host = request.headers.get("Host", "127.0.0.1")
    link = f"http://{host}/retail/reset?token={token}"
    from ...oracle import collab
    if host not in (f"127.0.0.1:{config.APP_PORT}", f"localhost:{config.APP_PORT}", "127.0.0.1"):
        # VULN(host-header-attacks): reset link built from an attacker Host header.
        engine.solve("host-header-poisoning", a, {"host": host, "link": link})
    session["_reset_token"] = token
    return {"ok": True, "sent": True}


@bp.route("/reset")
def reset_do():
    a = actor()
    token = request.args.get("token", "")
    email = request.args.get("email", "")
    minute = int(time.time() // 60)
    # VULN(password-reset-predictable-token): attacker can recompute the token.
    for m in (minute, minute - 1):
        if token == hashlib.md5(f"{email}:{m}".encode()).hexdigest() and email:
            u = db.query("SELECT id FROM users WHERE email=?", (email,), one=True)
            if u and a != f"user:{u['id']}":
                engine.solve("password-reset-predictable-token", a, {"email": email})
            return {"ok": True, "reset_for": email}
    return {"ok": False}, 400


@bp.route("/login-fixation", methods=["POST"])
def login_fixation():
    """VULN(session-fixation): adopt a caller-supplied session id, no rotation."""
    a = actor()
    sid = request.args.get("sid") or request.form.get("sid")
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    u = db.query("SELECT id,pw_md5 FROM users WHERE email=?", (email,), one=True)
    if u and u["pw_md5"] == _md5(password):
        if sid:
            session["sid"] = sid  # not regenerated on auth
            session["uid"] = u["id"]
            engine.solve("session-fixation", a, {"adopted_sid": sid})
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
        # VULN(weak-session-token): remember cookie is base64(uid:counter), forgeable.
        u = db.query("SELECT id,email FROM users WHERE id=?", (uid,), one=True)
        if u and a != f"user:{uid}":
            engine.solve("weak-session-token", a, {"forged_uid": uid})
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
    # VULN(credential-stuffing-no-lockout): failures never lock the account.
    if _login_fail[email] >= 6:
        engine.solve("credential-stuffing-no-lockout", a,
                     {"email": email, "attempts": _login_fail[email]})
    return {"ok": False}, 401


@bp.route("/oauth/authorize")
def oauth_authorize():
    a = actor()
    redirect_uri = request.args.get("redirect_uri", "")
    allow = (f"http://127.0.0.1:{config.APP_PORT}", f"http://localhost:{config.APP_PORT}")
    # VULN(oauth-redirect-abuse): redirect_uri not validated against a registry.
    if redirect_uri and not any(redirect_uri.startswith(x) for x in allow):
        engine.solve("oauth-redirect-abuse", a, {"redirect_uri": redirect_uri})
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
    # VULN(hash-length-extension): MAC is md5(secret || data), forgeable.
    if weak_mac(data) == mac:
        if "role=admin" in data:
            engine.solve("hash-length-extension", a, {"data": data})
        return {"ok": True, "data": data}
    return {"ok": False, "error": "bad mac"}, 400


_padding_probes = {}


@bp.route("/coupon/decrypt")
def coupon_decrypt():
    a = actor()
    enc = request.args.get("enc", "")
    _padding_probes.setdefault(a, set()).add(enc)
    # VULN(crypto-padding-oracle): distinguishable padding vs generic error.
    ok = (len(enc) % 32 == 0) and enc[-2:] != "zz"
    # a real padding-oracle attack sends many 1-byte-varied ciphertexts
    if len(_padding_probes[a]) > 50:
        engine.solve("padding-oracle", a, {"probes": len(_padding_probes[a])})
    return ({"padding": "valid"} if ok else ({"padding": "invalid"}, 400))


@bp.route("/promo/token")
def promo_token():
    import random
    # VULN(crypto-weak-randomness): seeded, non-crypto PRNG -> predictable.
    rng = random.Random(config.WEAK_RNG_SEED + session.get("promo_n", 0))
    tok = rng.randint(100000, 999999)
    session["promo_n"] = session.get("promo_n", 0) + 1
    session["promo_expected"] = tok
    return {"token": tok}


@bp.route("/promo/claim")
def promo_claim():
    a = actor()
    import random
    tok = request.args.get("token", type=int)
    rng = random.Random(config.WEAK_RNG_SEED + session.get("promo_n", 0))
    expected = rng.randint(100000, 999999)
    if tok == expected:
        engine.solve("weak-randomness-token", a, {"predicted": tok})
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
    from ...oracle import collab
    collab.arm_from_payload(body, "dangling-markup-exfil", a)
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
    # VULN(csrf): state-changing POST accepted with no anti-CSRF token, cross-site.
    if cross_site and not request.form.get("csrf_token"):
        engine.solve("csrf-change-email", a, {"origin": origin, "referer": referer})
    return {"ok": True}


@bp.route("/wallet/transfer")
def wallet_transfer():
    a = actor()
    # VULN(clickjacking): sensitive page served without frame protections.
    framed = request.args.get("framed") == "1" or \
        request.headers.get("Sec-Fetch-Dest") == "iframe"
    if framed:
        engine.solve("clickjacking", a, {"framed": True})
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
