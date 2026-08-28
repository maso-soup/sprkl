"""GUI smoke tests: pages render, the session flow works, and /admin stays hidden.

Complements the endpoint sweep (which proves oracle coverage). These assert the
human-facing storefront the sweep bypasses.
"""
import re
import requests
from conftest import BASE


PUBLIC_PAGES = ["/", "/products", "/products?category=Lime&sort=price", "/product/1",
                "/cart", "/checkout", "/search?q=lime", "/support", "/store-locator",
                "/about", "/press", "/status", "/newsletter/manage", "/promo?msg=hi",
                "/ref-landing?ref=hi", "/retail/login", "/robots.txt", "/sitemap.xml"]


def test_public_pages_render(server):
    for path in PUBLIC_PAGES:
        r = requests.get(server["base"] + path)
        assert r.status_code == 200, f"{path} -> {r.status_code}"


def test_login_cart_logout_session_flow(server):
    s = requests.Session()
    b = server["base"]
    # add to cart as guest; cart persists
    s.post(f"{b}/cart/add", data={"pid": "1", "qty": "2"})
    assert "SPRKL Classic" in s.get(f"{b}/cart").text
    # login -> dashboard, session persists
    s.post(f"{b}/retail/login", data={"email": "alice@example.com", "password": "password1"})
    dash = s.get(f"{b}/retail/dashboard")
    assert dash.status_code == 200 and "Dashboard" in dash.text
    assert "Hi, Alice" in s.get(f"{b}/").text            # nav reflects auth
    assert "SPRKL Classic" in s.get(f"{b}/cart").text     # cart survived login
    # account subpages reachable
    for p in ["/retail/orders", "/retail/wishlist", "/retail/giftcards",
              "/retail/wallet", "/retail/referrals", "/retail/profile", "/retail/security"]:
        assert s.get(b + p).status_code == 200, p
    # logout clears the session
    s.get(f"{b}/logout")
    assert s.get(f"{b}/retail/dashboard", allow_redirects=False).status_code in (301, 302)


def test_admin_is_hidden_but_reachable(server):
    b = server["base"]
    # reachable by direct browse
    assert requests.get(f"{b}/admin").status_code == 200
    # but NOT linked from the storefront, robots, or sitemap
    for path in ["/", "/products", "/retail/login", "/support", "/robots.txt", "/sitemap.xml"]:
        body = requests.get(b + path).text
        assert "/admin" not in body, f"/admin leaked in {path}"
        assert not re.search(r"\badmin\b", requests.get(f"{b}/robots.txt").text, re.I)


def test_admin_login_default_creds_reaches_console(server):
    s = requests.Session()
    b = server["base"]
    s.post(f"{b}/admin/login", data={"username": "admin", "password": "admin"})
    console = s.get(f"{b}/admin/console")
    assert console.status_code == 200 and "Admin Dashboard" in console.text
