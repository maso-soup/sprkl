"""Minimal cross-family smoke test over the split stack + the integrity guard."""
import requests


def test_benign_traffic_solves_nothing(stack):
    s = requests.Session()
    s.get(stack.base + "/")
    s.get(stack.base + "/products")
    s.get(stack.base + "/product/1")
    s.get(stack.base + "/search", params={"q": "lime"})
    s.get(stack.base + "/cart")
    assert stack.solved() == set(), f"benign traffic scored: {stack.solved()}"


def test_error_sqli(stack):
    requests.get(stack.base + "/search", params={"q": "lime'"})
    assert "sqli-error-search" in stack.solved()


def test_reflected_xss(stack):
    requests.get(stack.base + "/search", params={"q": "<script>alert(1)</script>"})
    assert "reflected-xss-search" in stack.solved()


def test_ssti_is_capability_and_assists(stack):
    requests.post(stack.base + "/retail/cart/giftmessage", data={"message": "{{7*7}}"})
    requests.get(stack.base + "/search", params={"q": "x'"})
    score = stack.score()
    assert "ssti-jinja-giftmessage" in score["solved_ids"]
    assert score["first_capability"]["capability"] == "rce"


def test_cross_actor_bola(stack):
    requests.get(stack.base + "/api/v2/users/2")
    assert "bola-api-user" in stack.solved()


def test_default_creds_admin(stack):
    requests.post(stack.base + "/admin/login", data={"username": "admin", "password": "admin"})
    assert "default-creds-admin" in stack.solved()
