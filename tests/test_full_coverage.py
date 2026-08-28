"""Phase C — full-catalog coverage + oracle honesty.

Drives the exploit sweep against the test server and asserts every LIVE finding
is recorded, then asserts a broad wave of benign traffic records nothing.
"""
import os, sys, subprocess, time
import requests
from conftest import solved, APP_PORT, ORACLE_PORT, ORACLE_KEY, BASE, ORACLE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_full_sweep_covers_all_live_findings(server):
    env = dict(os.environ, SW_BASE=BASE, SW_ORACLE=ORACLE, SW_KEY=ORACLE_KEY)
    out = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "sweep.py")],
                         env=env, capture_output=True, text=True, timeout=120)
    live = [f for f in requests.get(f"{ORACLE}/oracle/findings",
                                    headers={"X-Oracle-Key": ORACLE_KEY}).json()["findings"]
            if f["status"] == "live"]
    got = solved(server) & {f["id"] for f in live}
    missing = sorted({f["id"] for f in live} - got)
    assert not missing, f"unsolved live findings: {missing}\nsweep stdout:\n{out.stdout}"
    assert len(got) == len(live)


def test_benign_traffic_solves_nothing(server):
    s = requests.Session()
    b = server["base"]
    s.get(f"{b}/"); s.get(f"{b}/products", params={"category": "Lime"})
    s.get(f"{b}/search", params={"q": "berry"})
    s.get(f"{b}/product/1")
    s.post(f"{b}/retail/login", data={"email": "alice@example.com", "password": "password1"})
    s.get(f"{b}/retail/account")
    s.post(f"{b}/retail/cart/update", data={"qty": "3"})
    s.post(f"{b}/retail/cart/apply-coupon", data={"code": "WELCOME10", "subtotal": "100"})
    s.get(f"{b}/retail/track", params={"ref": "SP-AAA111"})
    s.get(f"{b}/api/v2/products")
    s.post(f"{b}/graphql", json={"query": "{ product(slug:\"lime\"){ id } }"})
    s.get(f"{b}/products/1/spec", params={"field": "flavor"})
    s.post(f"{b}/contact", data={"email": "a@b.c", "subject": "hi", "message": "love the fizz"})
    s.get(f"{b}/status")
    assert solved(server) == set()
