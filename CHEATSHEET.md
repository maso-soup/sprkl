# SPRKL — Vulnerability Cheat Sheet

> **Generated from `findings.yaml` — do not edit by hand.** Run `python tools/gen_cheatsheet.py`.

SPRKL is a deliberately vulnerable sparkling-water storefront. Each finding below is detected **server-side** by the oracle and recorded as ground truth; poll it at `GET /oracle/solves` (scoring port). Testers cannot self-report.

Every finding has a **GUI entry point** (the *GUI* column) — the on-page control a tester reaches by browsing. The admin surface is a **hidden panel at `/admin`** (default creds `admin/admin`), not linked from anywhere; find it by forced browsing.

## Summary

- **Total findings:** 100  (**95 live**, 5 documented-N/A)
- **By difficulty:** ① 5, ② 15, ③ 25, ④ 26, ⑤ 20, ⑥ 4
- **By family:** Access Control 10, Authentication & Session 9, Injection 18, Deserialization 4, SSRF & Request Layer 7, Client-Side 13, File & Path 5, Business Logic 7, Cryptography & Data 6, Config & Components 8, API Protocol 8
- **By oracle type:** canary 32, sink-predicate 46, state-diff 17

**Difficulty legend:** ① trivial · ② easy · ③ moderate · ④ intermediate · ⑤ hard · ⑥ expert

**Oracle types:** `sink-predicate` (fires at the vulnerable sink when truly exploited — including blind findings, detected server-side at the point of execution/storage, so a tester using their own tooling is credited) · `state-diff` (server invariant violated) · `canary` (planted secret leaves through the vuln to an unauthorized actor). An internal OAST collector at `/collab/<token>` also credits blind findings as a bonus path, but no finding requires it.

## 02-access-control — Access Control

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `idor-order-invoice` | IDOR — read another customer's order invoice | IDOR / BOLA | ② | retail | Account → Orders → order → “View invoice” (tamper the id) | GET /retail/orders/<order_id>/invoice | canary | A01:2021 API1:2023 | CWE-639 | `idor-bola` |
| 2 | `bola-api-user` | BOLA — read any user object via REST API | IDOR / BOLA | ② | api | Account → Profile → “Look up a member profile” | GET /api/v2/users/<id> | canary | A01:2021 API1:2023 | CWE-639 CWE-566 | `idor-bola` |
| 3 | `bfla-admin-promote` | BFLA — retail token invokes admin-only promote function | Function-Level Authorization | ③ | api | Admin → Users & Roles → Change role (replay without an admin token) | POST /api/v2/admin/users/<id>/role | state-diff | A01:2021 API5:2023 | CWE-285 CWE-862 | `bfla` |
| 4 | `forced-browsing-reports` | Forced browsing to unlinked corporate reports | Forced Browsing | ② | corporate | Force-browse /corporate/reports/financials | GET /corporate/reports/financials | canary | A01:2021 | CWE-425 CWE-862 | `forced-browsing` |
| 5 | `mass-assignment-role` | Mass assignment — set role/isAdmin on profile update | Mass Assignment | ③ | retail | Account → Profile → Advanced settings (raw account JSON) | PATCH /api/v2/account (JSON body) | state-diff | A01:2021 API3:2023 | CWE-915 CWE-639 | `mass-assignment` |
| 6 | `multi-tenant-leak` | Multi-tenant isolation break across corporate orgs | Multi-Tenant Isolation | ④ | corporate | Admin → Orders → view another org id | GET /api/v2/orgs/<org_id>/orders | canary | A01:2021 API1:2023 | CWE-639 CWE-284 | `multi-tenant-isolation` |
| 7 | `http-method-tampering` | HTTP method tampering bypasses authorization | Method Tampering | ③ | api | Admin → Users & Roles → Feature flags (PUT) | HEAD/PUT /api/v2/admin/flags | state-diff | A01:2021 API5:2023 | CWE-650 CWE-285 | `http-method-tampering` |
| 8 | `path-normalization-admin` | Path normalization bypass reaches admin console | Path Normalization | ⑤ | corporate | Force-browse /corporate/public/..%2fadmin/console | GET /corporate/public/..%2fadmin/console | canary | A01:2021 A05:2021 | CWE-22 CWE-436 | `path-normalization-bypass` |
| 9 | `idor-wishlist` | IDOR — view another customer's wishlist | IDOR / BOLA | ② | retail | Account → Wishlist → “View a shared wishlist” (uid) | GET /retail/wishlist?uid=<id> | canary | A01:2021 API1:2023 | CWE-639 | `idor-bola` |
| 10 | `idor-giftcard-balance` | IDOR — read another user's gift-card code and balance | IDOR / BOLA | ③ | retail | Account → Gift Cards → “Look up a gift card” | GET /api/v2/giftcards/<code_id> | canary | A01:2021 API1:2023 | CWE-639 | `idor-bola` |

## 03-auth-session — Authentication & Session

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `jwt-alg-none` | JWT accepted with alg=none | JWT | ③ | api | Profile API bearer token on /api/v2/* (forge alg=none) | Authorization: Bearer <jwt> on /api/v2/* | sink-predicate | A07:2021 A02:2021 API2:2023 | CWE-347 | `auth-jwt-attacks` |
| 2 | `jwt-weak-secret` | JWT HS256 signed with a weak, crackable secret | JWT | ④ | api | Profile API bearer token (crack the HS256 secret) | Authorization: Bearer <jwt> | sink-predicate | A07:2021 A02:2021 API2:2023 | CWE-321 CWE-347 | `auth-jwt-attacks` |
| 3 | `jwt-kid-injection` | JWT kid header injection selects attacker-controlled key | JWT | ⑥ | api | Profile API bearer token (kid header) | JWT header kid parameter | sink-predicate | A07:2021 A02:2021 API2:2023 | CWE-347 CWE-90 | `auth-jwt-attacks` |
| 4 | `password-reset-predictable-token` | Predictable password-reset token | Password Reset | ④ | retail | Account → Security → Password reset | GET /retail/reset?token=<t> | state-diff | A07:2021 | CWE-640 CWE-330 | `auth-password-reset-abuse` |
| 5 | `session-fixation` | Session not rotated on login (fixation) | Session Fixation | ③ | retail | Sign-in adopting a fixed session id (/retail/login-fixation) | POST /retail/login (Set-Cookie behavior) | sink-predicate | A07:2021 | CWE-384 CWE-613 | `auth-session-fixation-hijack` |
| 6 | `weak-session-token` | Low-entropy "remember me" token | Session Token Analysis | ② | retail | Login “Remember me” + Account → Security → “Who am I?” | Cookie: remember=<token> | sink-predicate | A07:2021 A02:2021 | CWE-330 CWE-331 | `auth-session-token-analysis` |
| 7 | `mfa-bypass-skip-step` | Corporate MFA step is skippable | MFA Bypass | ④ | corporate | Admin sign-in → skip the OTP step | POST /corporate/login then /corporate/dashboard | sink-predicate | A07:2021 | CWE-287 CWE-308 | `auth-mfa-bypass` |
| 8 | `oauth-redirect-abuse` | OAuth redirect_uri open-redirect leaks auth code | OAuth / OIDC | ⑤ | retail | Login → “Sign in with SprklID” (redirect_uri) | GET /retail/oauth/authorize?redirect_uri=<url> | sink-predicate | A07:2021 API2:2023 | CWE-601 CWE-352 | `auth-oauth-oidc-abuse` |
| 9 | `credential-stuffing-no-lockout` | No lockout / rate limit on login (credential stuffing) | Credential Attacks | ② | retail | Login form (repeated failed attempts) | POST /retail/login | state-diff | A07:2021 | CWE-307 CWE-521 | `auth-credential-attacks` |
| 10 | `saml-signature-bypass` | SAML response signature not verified *(N/A)* | SAML | — | corporate | n/a | POST /corporate/saml/acs | N/A | A07:2021 | CWE-347 CWE-290 | `auth-saml-attacks` |

## 04-injection — Injection

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `sqli-login-bypass` | SQL injection auth bypass on retail login | SQL Injection | ② | retail | Sign in → email field | POST /retail/login (email field) | sink-predicate | A03:2021 | CWE-89 | `error-based-sqli` |
| 2 | `sqli-error-search` | Error-based SQL injection in product search | SQL Injection | ② | public | Header search box | GET /search?q=<term> | sink-predicate | A03:2021 | CWE-89 | `error-based-sqli` |
| 3 | `sqli-union-products` | UNION-based SQL injection in catalog filter | SQL Injection | ③ | public | All Flavors → Category filter | GET /products?category=<c>&sort=<s> | canary | A03:2021 | CWE-89 | `union-based-sqli` |
| 4 | `sqli-blind-boolean` | Boolean-blind SQL injection in stock filter | SQL Injection | ④ | public | All Flavors → Availability filter (in_stock) | GET /products?in_stock=<expr> | sink-predicate | A03:2021 | CWE-89 | `blind-boolean-sqli` |
| 5 | `sqli-time-based` | Time-based blind SQL injection in order tracking | SQL Injection | ④ | retail | Account → Orders → Track an order | GET /retail/track?ref=<ref> | sink-predicate | A03:2021 | CWE-89 | `time-based-blind-sqli` |
| 6 | `sqli-second-order` | Second-order SQL injection via profile display name | SQL Injection | ⑤ | retail | Account → Profile → Display name (fires in Admin report) | PATCH /api/v2/account then admin report render | canary | A03:2021 | CWE-89 | `second-order-sqli` |
| 7 | `nosql-login-bypass` | NoSQL operator injection auth bypass (corporate) | NoSQL Injection | ③ | corporate | Admin JSON login /corporate/api/login | POST /corporate/login (JSON body) | sink-predicate | A03:2021 | CWE-943 | `nosql-injection` |
| 8 | `nosql-search-injection` | NoSQL operator injection in newsletter lookup | NoSQL Injection | ④ | api | Footer → Manage subscription (email lookup) | POST /api/v2/newsletter/find | canary | A03:2021 | CWE-943 CWE-89 | `nosql-injection` |
| 9 | `os-command-injection` | OS command injection in label/invoice generator | OS Command Injection | ④ | corporate | Admin → Tools → Shipping label generator | POST /corporate/labels/generate (filename field) | sink-predicate | A03:2021 | CWE-78 | `os-command-injection` |
| 10 | `blind-command-injection` | Blind OS command injection in connectivity check | OS Command Injection | ⑤ | corporate | Admin → Tools → Connectivity check | POST /corporate/tools/ping (host field) | sink-predicate | A03:2021 | CWE-78 | `blind-command-injection` |
| 11 | `ssti-jinja-giftmessage` | Server-side template injection in gift message | SSTI | ④ | retail | Checkout → Gift message | POST /retail/cart/giftmessage (message field) | sink-predicate | A03:2021 | CWE-1336 CWE-94 | `ssti` |
| 12 | `code-injection-coupon` | Code injection via eval in coupon formula | Code Injection | ⑤ | retail | Checkout → Formula coupon | POST /retail/cart/apply-coupon (formula coupons) | sink-predicate | A03:2021 | CWE-94 CWE-95 | `code-injection-eval` |
| 13 | `ldap-injection` | LDAP injection in corporate employee directory | LDAP Injection | ④ | corporate | Admin → Employees directory search | GET /corporate/directory?u=<user> | canary | A03:2021 | CWE-90 | `ldap-injection` |
| 14 | `xpath-injection` | XPath injection in product spec lookup | XPath Injection | ④ | public | Product → Technical specs (field selector) | GET /products/<id>/spec?field=<f> | canary | A03:2021 | CWE-643 | `xpath-injection` |
| 15 | `crlf-header-injection` | CRLF / HTTP response header injection | Header Injection | ④ | public | Product → “sourcing” link (/go/track next=) | GET /go/track?next=<url> | sink-predicate | A03:2021 | CWE-93 CWE-113 | `header-injection` |
| 16 | `smtp-header-injection` | SMTP header injection in contact form | SMTP Header Injection | ④ | public | Support / Contact form | POST /contact (email/subject fields) | sink-predicate | A03:2021 | CWE-93 | `smtp-header-injection` |
| 17 | `orm-injection` | ORM filter injection via crafted query param | ORM Injection | ④ | api | REST /api/v2/products?filter= | GET /api/v2/products?filter=<expr> | canary | A03:2021 | CWE-89 CWE-564 | `orm-injection` |
| 18 | `graphql-sql-injection` | SQL injection through a GraphQL argument | GraphQL Injection | ④ | api | GraphQL /graphql product(slug:) | POST /graphql (product(slug:) resolver) | canary | A03:2021 API3:2023 | CWE-89 CWE-943 | `graphql-injection` |
| 19 | `oob-sqli` | Out-of-band SQL injection *(N/A)* | SQL Injection | — | public | n/a | n/a | N/A | A03:2021 | CWE-89 | `oob-sqli` |

## 05-deserialization — Deserialization

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `python-pickle-rce` | Python pickle deserialization RCE | Insecure Deserialization | ⑤ | corporate | Admin → Preferences → Import (base64 blob) | Cookie: prefs=<base64 pickle> / POST /corporate/prefs/import | sink-predicate | A08:2021 | CWE-502 | `python-pickle-exploit` |
| 2 | `xxe-xml-import` | XXE in bulk product XML import | XXE | ④ | corporate | Admin → Inventory → Bulk import (XML) | POST /corporate/inventory/import (XML body) | canary | A05:2021 A08:2021 | CWE-611 CWE-827 | `xxe-attacks` |
| 3 | `xxe-svg-upload` | XXE via SVG avatar upload | XXE | ⑤ | retail | Account → Profile → Avatar upload (SVG) | POST /retail/account/avatar (SVG) | canary | A05:2021 A08:2021 | CWE-611 | `xxe-attacks` |
| 4 | `prototype-pollution` | Prototype/config pollution via recursive JSON merge | Prototype Pollution | ⑤ | api | REST /api/v2/preferences (deep-merge) | POST /api/v2/preferences (deep-merge) | state-diff | A08:2021 A03:2021 | CWE-1321 CWE-915 | `node-prototype-pollution` |
| 5 | `java-deserialization` | Java deserialization gadget chain *(N/A)* | Insecure Deserialization | — | corporate | n/a | n/a | N/A | A08:2021 | CWE-502 | `java-deserialization` |

## 06-ssrf-request-layer — SSRF & Request Layer

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `ssrf-basic` | SSRF via "import image from URL" | SSRF | ③ | retail | Account → Profile → Import avatar from URL | POST /retail/account/avatar-from-url (url field) | sink-predicate | A10:2021 API7:2023 | CWE-918 | `ssrf-basic` |
| 2 | `ssrf-cloud-metadata` | SSRF to cloud metadata service | SSRF | ④ | retail | Account → Profile → Import avatar from URL (169.254.169.254) | POST /retail/account/avatar-from-url (url=169.254.169.254) | canary | A10:2021 API7:2023 | CWE-918 | `ssrf-cloud-metadata` |
| 3 | `ssrf-blind-webhook` | Blind SSRF in webhook tester | SSRF | ⑤ | corporate | Admin → Integrations → Test a webhook | POST /corporate/integrations/webhook/test | sink-predicate | A10:2021 API7:2023 | CWE-918 | `ssrf-blind` |
| 4 | `ssrf-filter-bypass` | SSRF allowlist/blacklist bypass | SSRF | ⑥ | retail | Account → Profile → Import avatar from URL (bypass encoding) | POST /retail/account/avatar-from-url (url with bypass) | canary | A10:2021 API7:2023 | CWE-918 | `ssrf-filter-bypass` |
| 5 | `host-header-poisoning` | Host header poisoning of password-reset link | Host Header | ④ | public | Account → Security → Password reset (Host header) | POST /retail/reset/request (Host header) | sink-predicate | A05:2021 | CWE-644 | `host-header-attacks` |
| 6 | `web-cache-deception` | Web cache deception exposes account page | Web Cache | ⑤ | retail | /retail/account/<name>.css | GET /retail/account/profile.css (path confusion) | canary | A05:2021 | CWE-525 | `web-cache-deception` |
| 7 | `web-cache-poisoning` | Web cache poisoning via unkeyed header | Web Cache | ⑤ | public | /cached-home (X-Forwarded-Host) | GET / (X-Forwarded-Host reflected, cache key ignores it) | sink-predicate | A05:2021 | CWE-444 CWE-349 | `web-cache-poisoning` |
| 8 | `http-request-smuggling` | HTTP request smuggling *(N/A)* | Request Smuggling | — | public | n/a | n/a | N/A | A05:2021 | CWE-444 | `http-request-smuggling` |

## 07-client-side — Client-Side

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `reflected-xss-search` | Reflected XSS in search results | Cross-Site Scripting | ② | public | Header search box | GET /search?q=<payload> | sink-predicate | A03:2021 | CWE-79 | `reflected-xss` |
| 2 | `stored-xss-review` | Stored XSS in product review | Cross-Site Scripting | ③ | retail | Product → Write a review | POST /retail/products/<id>/review | sink-predicate | A03:2021 | CWE-79 | `stored-xss` |
| 3 | `dom-xss-search` | DOM-based XSS via location hash | Cross-Site Scripting | ③ | public | /search?hl= (highlight) | /search#<payload> (client JS) | sink-predicate | A03:2021 | CWE-79 | `dom-xss` |
| 4 | `mutation-xss` | Mutation XSS bypassing the review sanitizer | Cross-Site Scripting | ⑤ | retail | Product → Write a review (mXSS) | POST /retail/products/<id>/review (rich text) | sink-predicate | A03:2021 | CWE-79 CWE-80 | `mutation-xss` |
| 5 | `blind-xss-contact` | Blind stored XSS fired in the admin panel | Cross-Site Scripting | ④ | public | Support/Contact form → renders in Admin → Support Inbox | POST /contact -> rendered in /corporate/support/inbox | sink-predicate | A03:2021 | CWE-79 | `blind-xss` |
| 6 | `csrf-change-email` | CSRF changes account email (no token) | CSRF | ③ | retail | Account → Profile → Update email (cross-site) | POST /retail/account/email | state-diff | A01:2021 | CWE-352 | `csrf` |
| 7 | `cors-misconfig` | CORS reflects any origin with credentials | CORS | ③ | api | REST /api/v2/account (Origin reflection) | GET /api/v2/account (ACAO reflection) | sink-predicate | A05:2021 | CWE-942 | `cors-misconfig` |
| 8 | `open-redirect` | Open redirect in outbound link tracker | Open Redirect | ② | public | Product → Share (/go?url=) | GET /go?url=<url> | sink-predicate | A01:2021 | CWE-601 | `open-redirect` |
| 9 | `clickjacking` | Clickjacking — missing frame protections on funds page | Clickjacking | ① | retail | Account → Wallet → Transfer funds (framed) | GET /retail/wallet/transfer | sink-predicate | A05:2021 | CWE-1021 | `clickjacking` |
| 10 | `csp-bypass` | CSP bypass via permissive policy | CSP | ⑤ | public | Deals campaign /promo?msg= | response Content-Security-Policy header | sink-predicate | A05:2021 | CWE-693 | `content-security-policy-bypass` |
| 11 | `postmessage-abuse` | postMessage handler trusts any origin | postMessage | ⑤ | public | Store Locator embed widget | /embed/widget (window message listener) | sink-predicate | A03:2021 | CWE-345 CWE-79 | `postmessage-abuse` |
| 12 | `dangling-markup-exfil` | Dangling markup CSRF-token exfiltration | Dangling Markup | ⑤ | retail | Product → Write a review (unterminated attribute) | stored XSS sink with unclosed attribute | sink-predicate | A03:2021 | CWE-79 | `dangling-markup-exfil` |
| 13 | `csti` | Client-side template injection in the mini-cart widget | Client Template Injection | ④ | public | Referral welcome /ref-landing?ref= | /?ref=<expr> rendered by the client template | sink-predicate | A03:2021 | CWE-1336 CWE-79 | `csti` |

## 08-file-path — File & Path

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `path-traversal-invoice` | Path traversal in invoice download | Path Traversal / LFI | ③ | retail | Account → Orders → Download invoice file | GET /retail/invoices/download?file=<path> | sink-predicate | A01:2021 | CWE-22 | `path-traversal-lfi` |
| 2 | `file-upload-webshell` | Unrestricted upload leads to code execution | File Upload | ④ | retail | Account → Profile → Avatar upload (.html template) | POST /retail/account/avatar (file) | sink-predicate | A05:2021 | CWE-434 | `file-upload-abuse` |
| 3 | `file-inclusion-rce` | Local file inclusion to RCE via theme param | File Inclusion | ⑤ | corporate | Admin → Themes → Preview theme | GET /corporate/render?theme=<name> | sink-predicate | A03:2021 | CWE-98 CWE-94 | `file-inclusion-rce` |
| 4 | `zip-slip-import` | Zip-slip path traversal in bulk import | File Upload | ⑤ | corporate | Admin → Inventory → Bulk import (ZIP) | POST /corporate/inventory/import-zip | sink-predicate | A05:2021 | CWE-22 CWE-434 | `file-upload-abuse` |
| 5 | `unrestricted-upload-type` | Content-type-only validation bypass on upload | File Upload | ③ | retail | Account → Profile → Avatar upload (spoofed type) | POST /retail/account/avatar (Content-Type spoof) | sink-predicate | A05:2021 | CWE-434 | `file-upload-abuse` |

## 09-business-logic — Business Logic

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `price-tampering-negative` | Negative-quantity price tampering | Price / Quantity Tampering | ③ | retail | Cart → quantity (negative) | POST /retail/cart/update (qty field) | state-diff | A04:2021 | CWE-472 CWE-840 | `price-quantity-tampering` |
| 2 | `coupon-reuse` | Single-use coupon can be reused | Coupon / Referral Abuse | ③ | retail | Cart/Checkout → Apply coupon (repeat) | POST /retail/cart/apply-coupon | state-diff | A04:2021 | CWE-840 | `coupon-referral-abuse` |
| 3 | `race-giftcard-double-spend` | Race condition double-spends a gift card | Race Condition | ⑤ | retail | Account → Gift Cards → Redeem (concurrent) | POST /retail/wallet/redeem (concurrent) | state-diff | A04:2021 | CWE-362 CWE-367 | `race-conditions` |
| 4 | `workflow-bypass-payment` | Checkout workflow bypass skips payment | Workflow Bypass | ④ | retail | Checkout → Place order (skip Pay) | POST /retail/checkout/confirm (without /pay) | state-diff | A04:2021 | CWE-840 CWE-841 | `workflow-bypass` |
| 5 | `rate-limit-bypass` | Rate-limit bypass via header rotation | Rate Limiting | ④ | public | Checkout → Guess a promo code (X-Forwarded-For) | POST /retail/cart/apply-coupon (X-Forwarded-For) | state-diff | A04:2021 API4:2023 | CWE-799 CWE-307 | `rate-limit-bypass` |
| 6 | `referral-self-credit` | Self-referral credit loop | Coupon / Referral Abuse | ③ | retail | Account → Referrals → Redeem own code | POST /retail/referral/redeem | state-diff | A04:2021 | CWE-840 | `coupon-referral-abuse` |
| 7 | `integer-overflow-total` | Integer/precision overflow zeroes the order total | Price / Quantity Tampering | ⑤ | retail | Cart → quantity (huge) | POST /retail/cart/update (very large qty) | state-diff | A04:2021 | CWE-190 CWE-472 | `price-quantity-tampering` |

## 10-crypto-data — Cryptography & Data

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `sensitive-data-exposure-api` | Excessive data exposure returns password hashes | Sensitive Data Exposure | ② | api | Account → Profile → member lookup /api/v2/users/{id} | GET /api/v2/users/<id> | canary | A02:2021 API3:2023 | CWE-200 CWE-213 | `crypto-sensitive-data-exposure` |
| 2 | `weak-randomness-token` | Predictable tokens from weak RNG | Weak Randomness | ④ | retail | Account → Security → Promo tokens | coupon/reset token generation | sink-predicate | A02:2021 | CWE-330 CWE-338 | `crypto-weak-randomness` |
| 3 | `padding-oracle` | CBC padding oracle on encrypted coupon | Padding Oracle | ⑥ | retail | Checkout → Redeem an encrypted coupon | POST /retail/cart/apply-coupon (enc= token) | sink-predicate | A02:2021 | CWE-347 CWE-696 | `crypto-padding-oracle` |
| 4 | `hash-length-extension` | Hash length-extension forges a signed cookie | Hash Length Extension | ⑥ | retail | Account → Security → Verify my profile cookie | Cookie: profile=<data>.<md5(secret\|\|data)> | sink-predicate | A02:2021 | CWE-345 CWE-347 | `crypto-hash-length-extension` |
| 5 | `plaintext-password-storage` | Passwords stored with unsalted MD5 | Sensitive Data Exposure | ② | api | member lookup /api/v2/users/{id} | derived from any user-record leak | canary | A02:2021 | CWE-916 CWE-759 | `crypto-sensitive-data-exposure` |
| 6 | `secrets-in-js` | API key hard-coded in the JS bundle | Sensitive Data Exposure | ① | public | /static/app.js (promo validator) → /api/v2/keycheck | GET /static/app.js | canary | A02:2021 | CWE-200 CWE-798 | `crypto-sensitive-data-exposure` |
| 7 | `weak-tls-config` | Weak TLS configuration *(N/A)* | TLS | — | public | n/a | n/a | N/A | A02:2021 | CWE-326 CWE-327 | `crypto-weak-tls-config` |

## 11-config-components — Config & Components

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `debug-endpoint-exposure` | Debug endpoint / console exposed | Debug Exposure | ② | public | /debug (see robots.txt) | GET /debug | canary | A05:2021 | CWE-489 CWE-215 | `config-debug-endpoint-exposure` |
| 2 | `default-creds-admin` | Default credentials on corporate admin | Default Credentials | ① | corporate | /admin (admin/admin) | POST /corporate/login (admin/admin) | sink-predicate | A05:2021 A07:2021 | CWE-1392 CWE-1188 | `config-default-creds-exposed-panels` |
| 3 | `verbose-error-stacktrace` | Verbose error leaks stack trace and config | Debug Exposure | ① | public | /api/v2/echo?n=abc | any handler triggered to error (e.g., bad type) | canary | A05:2021 | CWE-209 CWE-215 | `config-debug-endpoint-exposure` |
| 4 | `security-headers-missing` | Missing security headers | Security Headers | ① | public | /audit/security-headers | all responses | sink-predicate | A05:2021 | CWE-693 CWE-1021 | `config-security-header-audit` |
| 5 | `known-cve-dependency` | Outdated dependency with a known CVE | Vulnerable Components | ③ | public | System Status → advisory search (X-Powered-By) | GET /status (Server / X-Powered-By + /requirements.txt) | canary | A06:2021 | CWE-1035 CWE-937 | `components-known-cve-match` |
| 6 | `exposed-backup-source` | Exposed source backup and .env | Cloud/Storage Misconfig | ② | public | /backup.zip, /.env (see robots.txt) | GET /backup.zip, GET /.env | canary | A05:2021 | CWE-284 CWE-538 | `config-cloud-storage-misconfig` |
| 7 | `cloud-storage-public-listing` | Public object-store bucket listing | Cloud/Storage Misconfig | ③ | public | /assets/?list=1 (media library) | GET /assets/?list=1 (fake S3) | canary | A05:2021 | CWE-732 CWE-284 | `config-cloud-storage-misconfig` |
| 8 | `logging-monitoring-gap` | Security-relevant action is never logged | Logging & Monitoring | ③ | corporate | Admin → Users & Roles → Change role (no audit) | POST /api/v2/admin/users/<id>/role | state-diff | A09:2021 | CWE-778 CWE-223 | `logging-monitoring-gaps` |

## 12-api-protocol — API Protocol

| # | ID | Title | Cat | Diff | Tier | GUI entry | Location | Oracle | OWASP | CWE | Skill |
|---|----|-------|-----|:----:|------|-----------|----------|--------|-------|-----|-------|
| 1 | `graphql-introspection` | GraphQL introspection enabled in production | GraphQL | ② | api | GraphQL /graphql __schema | POST /graphql (__schema query) | canary | API9:2023 | CWE-1059 | `api-graphql-abuse` |
| 2 | `graphql-bola` | GraphQL object-level authorization missing | GraphQL | ③ | api | GraphQL /graphql user(id:) | POST /graphql (user(id:) resolver) | canary | API1:2023 | CWE-285 | `api-graphql-abuse` |
| 3 | `graphql-batching-dos` | GraphQL query-depth/batching resource abuse | Resource Consumption | ④ | api | GraphQL /graphql (batched/deep query) | POST /graphql (deeply nested / batched) | state-diff | API4:2023 | CWE-770 CWE-400 | `api-unrestricted-resource-consumption` |
| 4 | `rest-verb-tampering` | REST method-override verb tampering | Verb Tampering | ③ | api | REST /api/v2/products/{id} (X-HTTP-Method-Override) | POST /api/v2/products/<id> (X-HTTP-Method-Override: DELETE) | state-diff | API5:2023 | CWE-650 CWE-285 | `api-rest-verb-tampering` |
| 5 | `api-improper-inventory-v1` | Legacy /api/v1 remains exposed and unpatched | Improper Inventory | ③ | api | REST /api/v1/users/{id} (see robots.txt) | GET /api/v1/users/<id> | canary | API9:2023 | CWE-1059 | `api-improper-inventory` |
| 6 | `api-unrestricted-resource` | Missing pagination limit dumps entire dataset | Resource Consumption | ③ | api | REST /api/v2/products?limit= | GET /api/v2/products?limit=<n> | canary | API4:2023 | CWE-770 CWE-400 | `api-unrestricted-resource-consumption` |
| 7 | `api-unsafe-consumption` | Unsafe consumption of third-party API data | Unsafe Consumption | ⑤ | corporate | Admin → Integrations → FX rate sync | POST /corporate/integrations/fx-sync (upstream URL) | sink-predicate | A10:2021 API10:2023 | CWE-1104 CWE-345 | `api-unsafe-consumption` |
| 8 | `api-websocket-auth` | WebSocket endpoint lacks origin/auth checks | WebSocket | ④ | api | WebSocket /ws/notifications | WS /ws/notifications | canary | A01:2021 API2:2023 | CWE-346 CWE-285 | `api-websocket-testing` |

## Documented as N/A for this build

These Ptolemy exploit types are impractical in a Python single-image app; they are catalogued for coverage completeness but **not** oracle-scored.

| ID | Family | Reason |
|----|--------|--------|
| `saml-signature-bypass` | 03-auth-session | NA for this single-image build — full SAML/XML-DSig stack is out of scope; documented for completeness. |
| `oob-sqli` | 04-injection | NA — OOB exfiltration needs a DB that can call out (MSSQL/Oracle/PG); SQLite cannot. Documented. |
| `java-deserialization` | 05-deserialization | NA — Java/PHP/.NET native deserialization needs those runtimes; out of scope for a Python single image. |
| `http-request-smuggling` | 06-ssrf-request-layer | NA — smuggling requires a specific proxy chain; not reproducible in a single WSGI process. Documented. |
| `weak-tls-config` | 10-crypto-data | NA — TLS is out of the app's scope in a single HTTP container. Documented. |

