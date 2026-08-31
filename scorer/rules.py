"""THE ANSWER KEY — scorer-side only, never in the app image.

finding id -> predicate over one sealed bundle. Every rule that returns true
records a solve; rules are not mutually exclusive, so one request can solve
several findings (a UNION payload that also errors is both).

`capability=` marks a finding that hands the tester leverage over the rest of
the benchmark. Solves an actor makes after their first capability solve are
tagged assisted and scored separately.

`prereq=` lists path prefixes a genuine solver would almost certainly have
visited first; missing prerequisites raise the solve's cheat score.
"""
import re
from .engine import rule

# Detection predicates. These used to live in app/util.py as looks_xss() /
# looks_mutation_xss() / dangerous_pickle(); they encode what "exploited" means,
# so they belong here.
XSS = re.compile(r"<script|</script|onerror\s*=|onload\s*=|onmouseover\s*=|"
                 r"onfocus\s*=|<img|<svg|<iframe|javascript:|<body|<video|<details", re.I)
MUTATION = re.compile(r"<noscript|<template|<xmp|<math|<style|<textarea|<title", re.I)
DANGLING = re.compile(r"<\w+[^>]*=\s*['\"][^'\"]*$")
EXPR = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}")
SQL_META = re.compile(r"['\"]|\bunion\b|\bselect\b|--|/\*", re.I)


# ===========================================================================
# 04 · injection — SQL
# ===========================================================================

@rule("sqli-error-search", prereq=["/search"])
def _(r):
    return r.path == "/search" and r.any(
        "sql.exec", lambda e: e.error and not e.parameterised)


@rule("sqli-union-products", prereq=["/products"])
def _(r):
    return bool(r.leaked()) and r.any(
        "sql.exec", lambda e: "union" in (e.sql or "").lower() and not e.parameterised)


@rule("sqli-blind-boolean", prereq=["/products"])
def _(r):
    # Char-by-char extraction: the statement reaches the secret column through
    # a comparison primitive, and it was never parameterised.
    return r.any("sql.exec", lambda e: not e.parameterised and e.sql
                 and re.search(r"secret", e.sql, re.I)
                 and re.search(r"substr|glob|like|hex\(|unicode\(|<|>", e.sql, re.I))


@rule("sqli-time-based", prereq=["/retail/login", "/products"])
def _(r):
    # Proxy-measured latency, so the app cannot fake it either way.
    return r.ms > 900 and r.any(
        "sql.exec", lambda e: not e.parameterised and (e.ms or 0) > 900)


# ===========================================================================
# 04 · injection — other interpreters
# ===========================================================================

@rule("xpath-injection", prereq=["/products"])
def _(r):
    return bool(r.leaked()) and r.any(
        "xpath.eval", lambda e: e.field and re.search(r"[\[\]|*@/]|\bor\b", e.field, re.I))


@rule("smtp-header-injection", prereq=["/contact"])
def _(r):
    return r.any("mail.send", lambda e: any(
        str(h).lower().startswith(("bcc", "cc")) for h in (e.headers or [])))


@rule("crlf-header-injection", prereq=["/go/track"])
def _(r):
    # Proxy-observed: an injected header actually appears in the response the
    # tester received. No app cooperation, and no way to fake it.
    injected = {"x-sprkl-next"}
    base = {k for k in r.res_headers}
    for v in r.args.values():
        if v and re.search(r"[\r\n]|%0d|%0a", v, re.I) and ":" in v:
            candidate = v.split(":")[0].split("\n")[-1].split("\r")[-1].strip().lower()
            if candidate and candidate in base - injected:
                return True
    return False


# ===========================================================================
# 07 · client-side — all proxy-observed
# ===========================================================================

@rule("reflected-xss-search", prereq=["/search"])
def _(r):
    return bool(r.reflected(pred=XSS.search))


@rule("dom-xss-search", prereq=["/search"])
def _(r):
    hl = r.args.get("hl")
    return bool(hl and XSS.search(hl) and hl in r.body)


@rule("stored-xss-review", prereq=["/product/"])
def _(r):
    # A submitted payload carrying a plain XSS vector is served back verbatim.
    return any(XSS.search(p) and not MUTATION.search(p)
               for p in r.stored_hits(lambda _p: True))


@rule("mutation-xss", prereq=["/product/"])
def _(r):
    return bool(r.stored_hits(lambda p: MUTATION.search(p)))


@rule("dangling-markup-exfil", prereq=["/product/"])
def _(r):
    return bool(r.stored_hits(lambda p: DANGLING.search(p)))


@rule("csti", prereq=["/ref-landing"])
def _(r):
    ref = r.args.get("ref")
    return bool(ref and EXPR.search(ref) and ref in r.body)


@rule("blind-xss-contact", prereq=["/contact"])
def _(r):
    return r.any("cache.store", lambda e: e.store == "contacts"
                 and XSS.search(e.value or ""))


@rule("clickjacking", prereq=["/retail/wallet"])
def _(r):
    # Passive weakness, credited on deliberate probing: the tester frames the
    # sensitive page (?framed=1 / Sec-Fetch-Dest: iframe) and it carries no frame
    # protection. Scoped to intent so ordinary browsing never trips it.
    framed = r.args.get("framed") == "1" or r.headers.get("sec-fetch-dest") == "iframe"
    return (r.path == "/retail/wallet/transfer" and framed
            and "x-frame-options" not in r.res_headers
            and "frame-ancestors" not in (r.res_headers.get("content-security-policy") or ""))


@rule("security-headers-missing", prereq=["/audit"])
def _(r):
    # Credited when the tester deliberately audits headers, not on every page.
    return r.path == "/audit/security-headers" and not (
        {"x-frame-options", "content-security-policy", "x-content-type-options"}
        & set(r.res_headers))


@rule("cors-misconfig")
def _(r):
    origin = r.headers.get("origin")
    acao = r.res_headers.get("access-control-allow-origin")
    return bool(origin) and (acao == origin or acao == "*") and \
        (r.res_headers.get("access-control-allow-credentials") or "").lower() == "true"


@rule("open-redirect", prereq=["/go/track"])
def _(r):
    loc = r.res_headers.get("location") or ""
    if not (300 <= r.status < 400) or not loc:
        return False
    external = re.match(r"https?://|//", loc)
    return bool(external) and any(v and v in loc for v in r.args.values())


# ===========================================================================
# 08 · file & path — proxy-observed where possible
# ===========================================================================

@rule("path-normalization-admin", prereq=["/admin"])
def _(r):
    # Raw bytes as sent, which is exactly why the proxy is hand-rolled.
    target = r.target.split("?")[0]
    return (r.status < 400 and "/admin" in target.lower()
            and bool(re.search(r"%2e|%2f|%5c|//|/\.\./", target, re.I)))


# ===========================================================================
# 02 · access control — canary leaks to a non-owner (one shape, many findings)
# ===========================================================================

@rule("bola-api-user", prereq=["/api/v2/users"])
def _(r):
    return r.path.startswith("/api/v2/users/") and bool(r.leaked(kind="user-secret"))


@rule("idor-order-invoice", prereq=["/retail/orders"])
def _(r):
    return "/invoice" in r.path and bool(r.leaked(kind="order-secret"))


@rule("idor-giftcard-balance", prereq=["/api/v2/giftcards"])
def _(r):
    return r.path.startswith("/api/v2/giftcards/") and bool(r.leaked(kind="giftcard-secret"))


@rule("idor-wishlist", prereq=["/retail/wishlist"])
def _(r):
    return r.path.startswith("/retail/wishlist") and bool(r.leaked(kind="wishlist-secret"))


@rule("multi-tenant-leak", prereq=["/api/v2/orgs"])
def _(r):
    return "/orgs/" in r.path and bool(r.leaked(kind="order-secret"))


@rule("sensitive-data-exposure-api", prereq=["/api/v2/users"])
def _(r):
    # A full user row (password hash) crossing to a non-owner.
    return (r.path.startswith("/api/v2/users/") and "pw_md5" in (r.body or "")
            and bool(r.leaked(kind="user-secret")))


@rule("plaintext-password-storage", prereq=["/api/v2/users"])
def _(r):
    # The scorer hashes the manifest password itself and looks for the digest;
    # no app cooperation, so this is judged from proxy-observed bytes alone.
    import hashlib
    body = r.body or ""
    for a in r.m["accounts"]:
        pw = a.get("password")
        if pw and hashlib.md5(pw.encode()).hexdigest() in body \
                and a["principal"] not in r.principals:
            return True
    return False


@rule("api-improper-inventory-v1", prereq=["/api/v1"])
def _(r):
    return r.path.startswith("/api/v1/") and bool(r.leaked())


@rule("forced-browsing-reports")
def _(r):
    return "/reports/" in r.path and bool(r.leaked(kind="order-secret"))


@rule("graphql-bola", prereq=["/graphql"])
def _(r):
    return r.path == "/graphql" and bool(r.leaked(kind="user-secret"))


@rule("graphql-introspection", prereq=["/graphql"])
def _(r):
    return r.path == "/graphql" and bool(r.leaked())  # hidden type carries a canary


@rule("graphql-sql-injection", prereq=["/graphql"])
def _(r):
    return r.path == "/graphql" and r.any(
        "sql.exec", lambda e: not e.parameterised and "products" in (e.sql or "")
        and re.search(r"union|'", e.sql or "", re.I))


# ===========================================================================
# 11 · config / components — exposed secrets (canary in body OR header)
# ===========================================================================

@rule("debug-endpoint-exposure", capability="source-read")
def _(r):
    return r.path == "/debug" and bool(r.leaked(kind="debug"))


@rule("verbose-error-stacktrace")
def _(r):
    return r.status >= 500 and bool(r.leaked(kind="debug"))


@rule("exposed-backup-source", capability="source-read")
def _(r):
    return r.path in ("/.env", "/backup.zip") and bool(r.leaked(kind="env"))


@rule("cloud-storage-public-listing")
def _(r):
    return r.path.startswith("/assets") and bool(r.leaked(kind="planted"))


@rule("secrets-in-js")
def _(r):
    # The JS key validates here: the tester submits a secret they were never given.
    return r.path == "/api/v2/keycheck" and bool(r.submitted(kind="js-key"))


@rule("known-cve-dependency")
def _(r):
    # Marker rides in X-Powered-By; leaked() scans headers too.
    return bool(r.leaked(kind="cve"))


@rule("web-cache-deception")
def _(r):
    return r.any("cache.store", lambda e: e.hit) and bool(r.leaked(kind="user-secret"))


@rule("web-cache-poisoning")
def _(r):
    return r.path == "/cached-home" and r.any(
        "cache.store", lambda e: e.hit and e.keyed_on_header is False) \
        and (r.res_header_all("content-type") and "169" not in (r.body or ""))


@rule("api-websocket-auth", prereq=["/ws"])
def _(r):
    return r.any("ws.message", lambda e: not e.authenticated and e.origin) \
        and bool(r.leaked(kind="user-secret"))


# ===========================================================================
# 04 · injection — remaining interpreters (app-reported)
# ===========================================================================

@rule("nosql-search-injection", prereq=["/api/v2/newsletter"])
def _(r):
    return r.any("nosql.find", lambda e: e.operators)


@rule("nosql-login-bypass", prereq=["/admin"])
def _(r):
    return (r.any("auth.result", lambda e: e.ok and not e.password_verified
                  and e.mechanism == "document-store")
            and r.any("nosql.find", lambda e: e.operators))


@rule("ldap-injection", prereq=["/admin/directory"])
def _(r):
    return r.any("ldap.search", lambda e: e.arg
                 and re.search(r"[()*|&=]", e.arg)) and bool(r.leaked(kind="planted"))


@rule("orm-injection", prereq=["/api/v2/products"])
def _(r):
    return r.path == "/api/v2/products" and r.any(
        "sql.exec", lambda e: not e.parameterised and e.error is None) \
        and bool(r.leaked(kind="product-secret"))


@rule("sqli-second-order", prereq=["/api/v2/admin/report"])
def _(r):
    return "/admin/report" in r.path and bool(r.leaked(kind="user-secret"))


@rule("graphql-batching-dos", prereq=["/graphql"])
def _(r):
    return r.any("obj.assign", lambda e: e.target == "graphql.query"
                 and ((e.aliases or 0) >= 20 or (e.depth or 0) >= 12))


# ===========================================================================
# 03 · auth / session — the auth.result tap
# ===========================================================================

@rule("sqli-login-bypass", prereq=["/retail/login"])
def _(r):
    return (r.any("auth.result", lambda e: e.ok and not e.password_verified
                  and e.mechanism == "password")
            and r.any("sql.exec", lambda e: not e.parameterised))


@rule("default-creds-admin", prereq=["/admin"])
def _(r):
    return r.any("auth.result", lambda e: e.ok and e.password_verified
                 and e.user in {a["email"] for a in r.m["accounts"]
                                if a.get("default_credential")}
                 or (e.ok and e.password_verified and e.user == "admin"))


@rule("credential-stuffing-no-lockout", prereq=["/retail"])
def _(r):
    return r.any("auth.result", lambda e: (e.consecutive_failures or 0) >= 6
                 and not e.locked)


@rule("mfa-bypass-skip-step")
def _(r):
    return r.any("auth.result", lambda e: e.mechanism == "mfa" and e.ok
                 and set(e.steps_completed or []) < set(e.steps_required or []))


@rule("session-fixation", prereq=["/retail"])
def _(r):
    return r.any("auth.result", lambda e: e.ok and e.adopted_sid
                 and e.session_rotated is False)


@rule("weak-session-token")
def _(r):
    return r.any("auth.result", lambda e: e.mechanism == "remember-cookie"
                 and e.ok and e.token_signed is False) and bool(r.leaked(kind="user-secret"))


@rule("password-reset-predictable-token")
def _(r):
    return r.path == "/retail/reset" and r.any(
        "auth.result", lambda e: e.mechanism == "reset-token" and e.ok)


@rule("jwt-alg-none", prereq=["/api"])
def _(r):
    return r.any("auth.result", lambda e: e.mechanism == "jwt" and e.ok
                 and e.verified_by == "alg-none")


@rule("jwt-kid-injection", prereq=["/api"])
def _(r):
    return r.any("auth.result", lambda e: e.mechanism == "jwt" and e.ok
                 and e.verified_by == "kid-injection")


@rule("jwt-weak-secret", prereq=["/api"])
def _(r):
    return r.any("auth.result", lambda e: e.mechanism == "jwt" and e.ok
                 and e.verified_by == "hs256" and e.claimed_role == "admin"
                 and e.stored_role != "admin")


# ===========================================================================
# 05 · deserialization / file exec — capability findings
# ===========================================================================

@rule("python-pickle-rce", capability="rce")
def _(r):
    return r.any("deser.load", lambda e: e.fmt == "pickle" and any(
        op in (e.opcodes or "") for op in ("GLOBAL", "REDUCE", "STACK_GLOBAL")))


@rule("file-inclusion-rce", capability="rce")
def _(r):
    return r.any("tmpl.render", lambda e: e.from_path and r.escaped_root(e))


@rule("file-upload-webshell", capability="rce")
def _(r):
    return r.any("tmpl.render", lambda e: e.stored_upload
                 and EXPR.search(e.source or "") and e.result != e.source)


@rule("zip-slip-import", capability="rce")
def _(r):
    return r.any("archive.extract", lambda e: r.escaped_root(e))


@rule("code-injection-coupon", capability="rce")
def _(r):
    return r.any("code.eval", lambda e: e.source and re.search(
        r"__|import|globals|builtins|os\.|subprocess|open\(", e.source))


@rule("ssti-jinja-giftmessage", capability="rce")
def _(r):
    return r.any("tmpl.render", lambda e: not e.from_path
                 and EXPR.search(e.source or "") and e.result != e.source)


@rule("os-command-injection", capability="rce")
def _(r):
    return r.any("proc.exec", lambda e: e.shell and (e.extra_output_lines or 0) > 0
                 and any(c in (e.arg or "") for c in (";", "|", "&&", "$(", "`")))


@rule("blind-command-injection", capability="rce")
def _(r):
    return r.any("proc.exec", lambda e: e.shell and e.stdout_returned is False
                 and any(c in (e.arg or "") for c in (";", "|", "&&", "$(", "`")))


# ===========================================================================
# 08 · file & path — the fs.read / xml.parse taps
# ===========================================================================

@rule("path-traversal-invoice", capability="source-read", prereq=["/retail/invoices"])
def _(r):
    return r.any("fs.read", lambda e: r.escaped_root(e) and e.found)


@rule("xxe-xml-import", prereq=["/admin/inventory"])
def _(r):
    return r.any("xml.parse", lambda e: e.external_entities) \
        and bool(r.leaked(kind="xxe-file"))


@rule("xxe-svg-upload", prereq=["/retail/account/avatar"])
def _(r):
    return r.any("xml.parse", lambda e: e.external_entities and e.source == "svg") \
        and bool(r.leaked(kind="xxe-file"))


@rule("unrestricted-upload-type", prereq=["/retail/account/avatar"])
def _(r):
    return r.any("obj.assign", lambda e: e.target == "uploads"
                 and (e.declared_content_type or "").startswith("image/")
                 and e.extension not in (".png", ".jpg", ".jpeg", ".gif"))


# ===========================================================================
# 06 · SSRF — the net.fetch tap, judged against the manifest
# ===========================================================================

@rule("ssrf-basic", prereq=["/retail/account/avatar-from-url"])
def _(r):
    return r.any("net.fetch", lambda e: r.is_internal(e.resolved_ip)
                 and not e.blocked_by_filter)


@rule("ssrf-cloud-metadata")
def _(r):
    return r.any("net.fetch", lambda e: e.resolved_ip == "169.254.169.254") \
        or bool(r.leaked(kind="iam"))


@rule("ssrf-filter-bypass")
def _(r):
    # Reached internal space through a host the literal blocklist did not catch.
    return r.any("net.fetch", lambda e: r.is_internal(e.resolved_ip)
                 and not e.blocked_by_filter and e.host not in ("127.0.0.1", "localhost"))


@rule("ssrf-blind-webhook", prereq=["/admin/integrations"])
def _(r):
    return "/webhook" in r.path and r.any(
        "net.fetch", lambda e: r.is_internal(e.resolved_ip))


@rule("api-unsafe-consumption", prereq=["/admin/integrations"])
def _(r):
    return "/fx-sync" in r.path and r.any(
        "net.fetch", lambda e: r.is_internal(e.resolved_ip) or e.resolved_ip == "169.254.169.254")


# ===========================================================================
# 09 · business logic — state facts the app reports plainly
# ===========================================================================

@rule("coupon-reuse", prereq=["/retail/cart"])
def _(r):
    return r.any("coupon.redeem", lambda e: e.single_use and (e.prior_redemptions or 0) >= 1)


@rule("price-tampering-negative", prereq=["/retail/cart"])
def _(r):
    return r.any("order.total", lambda e: (e.subtotal or 0) < 0)


@rule("integer-overflow-total", prereq=["/retail/cart"])
def _(r):
    return r.any("order.total", lambda e: abs(
        (e.qty or 0) * (e.unit_price or 0) - (e.total or 0)) > 0.01)


@rule("workflow-bypass-payment", prereq=["/retail/checkout"])
def _(r):
    return r.any("order.finalize", lambda e: e.confirmed
                 and any(s not in (e.steps or []) for s in (e.required or [])))


@rule("race-giftcard-double-spend", prereq=["/retail/wallet"])
def _(r):
    seen = r.state.setdefault("gc", {})
    for e in r.ev("giftcard.redeem"):
        prev = seen.get(e.code)
        seen[e.code] = e.balance_before
        if prev is not None and prev == e.balance_before:
            return True
    return False


@rule("referral-self-credit", prereq=["/retail/referral"])
def _(r):
    return r.any("obj.assign", lambda e: e.target == "referrals.redeemed_by"
                 and e.owner_uid == e.redeemer_uid and e.redeemer_uid is not None)


@rule("rate-limit-bypass", prereq=["/retail/cart"])
def _(r):
    return r.any("obj.assign", lambda e: e.target == "ratelimit"
                 and (e.distinct_buckets or 0) >= 5 and (e.attempts or 0) > 10)


# ===========================================================================
# 12 · API / protocol — obj.assign + headers
# ===========================================================================

@rule("mass-assignment-role", prereq=["/api/v2/account"])
def _(r):
    return r.any("obj.assign", lambda e: e.target == "users"
                 and e.before != e.after and e.after in ("admin", "buyer"))


@rule("bfla-admin-promote", prereq=["/api/v2/admin"])
def _(r):
    return r.any("obj.assign", lambda e: e.target == "users.role"
                 and e.privileged and e.caller_role != "admin")


@rule("logging-monitoring-gap")
def _(r):
    return r.any("obj.assign", lambda e: e.target == "users.role"
                 and e.privileged and (e.audit_rows or 0) == 0)


@rule("http-method-tampering", prereq=["/api/v2/admin/flags"])
def _(r):
    return r.method in ("PUT", "HEAD") and r.any(
        "obj.assign", lambda e: e.target == "flags" and not e.guarded)


@rule("rest-verb-tampering", prereq=["/api/v2/products"])
def _(r):
    return r.any("obj.assign", lambda e: e.target == "products.listed"
                 and e.effective_method != e.wire_method and not e.authorized)


@rule("prototype-pollution", prereq=["/api/v2/preferences"])
def _(r):
    return r.any("obj.assign", lambda e: e.target == "prefs.defaults"
                 and "__proto__" in (e.keys or []) and not e.filtered)


@rule("api-unrestricted-resource", prereq=["/api/v2/products"])
def _(r):
    return r.path == "/api/v2/products" and "limit" in r.args \
        and bool(r.leaked(kind="product-secret"))


# ===========================================================================
# remaining client-side + crypto
# ===========================================================================

@rule("csrf-change-email", prereq=["/retail/account"])
def _(r):
    return r.any("obj.assign", lambda e: e.target == "users.email"
                 and e.cross_site and not e.csrf_token_present
                 and not e.csrf_token_required is None)


@rule("csp-bypass", prereq=["/promo"])
def _(r):
    csp = r.res_headers.get("content-security-policy") or ""
    return r.path == "/promo" and bool(r.reflected(pred=XSS.search)) \
        and ("unsafe-inline" in csp or not csp)


@rule("postmessage-abuse", prereq=["/embed/widget"])
def _(r):
    msg = r.args.get("msg")
    return bool(msg and (XSS.search(msg) or "fetch(" in msg) and msg in r.body)


@rule("oauth-redirect-abuse", prereq=["/retail/oauth"])
def _(r):
    loc = r.res_headers.get("location") or ""
    uri = r.args.get("redirect_uri", "")
    return bool(uri) and re.match(r"https?://|//", uri) and uri.split("?")[0] in loc


@rule("host-header-poisoning")
def _(r):
    host = r.headers.get("host", "")
    return r.any("token.issue", lambda e: e.host_from_header and e.link
                 and host and host in (e.link or "")
                 and host not in ("x", "sprkl.local", "127.0.0.1"))


@rule("weak-randomness-token", prereq=["/retail/promo"])
def _(r):
    return r.any("token.issue", lambda e: e.kind == "promo-claim" and e.matched)


@rule("hash-length-extension", prereq=["/retail/profile"])
def _(r):
    return r.any("auth.result", lambda e: e.mechanism == "mac-cookie" and e.ok
                 and "role=admin" in (e.data or ""))


@rule("padding-oracle", prereq=["/retail/coupon"])
def _(r):
    # Many single-byte-varied probes distinguished by response — a proxy-visible
    # pattern: N distinct ciphertexts to /coupon/decrypt with 200/400 split.
    seen = r.state.setdefault("padding", {})
    if r.path == "/retail/coupon/decrypt":
        actor = r.actor
        s = seen.setdefault(actor, set())
        s.add(r.args.get("enc", ""))
        return len(s) > 50
    return False
