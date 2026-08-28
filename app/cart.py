"""Session-backed shopping cart (persists across navigation until logout)."""
from flask import session
from . import db

PRICE_FALLBACK = 3.50


def _cart():
    return session.setdefault("cart", [])


def add(pid, qty=1):
    cart = _cart()
    for item in cart:
        if item["pid"] == pid:
            item["qty"] += qty
            break
    else:
        cart.append({"pid": pid, "qty": qty})
    session.modified = True


def set_qty(pid, qty):
    cart = _cart()
    for item in cart:
        if item["pid"] == pid:
            item["qty"] = qty
    session.modified = True


def remove(pid):
    session["cart"] = [i for i in _cart() if i["pid"] != pid]
    session.modified = True


def clear():
    session["cart"] = []
    session.modified = True


def lines():
    """Return cart lines joined with product info, plus subtotal."""
    out, subtotal = [], 0.0
    for item in _cart():
        p = db.query("SELECT id,name,flavor,price FROM products WHERE id=?",
                     (item["pid"],), one=True)
        price = p["price"] if p else PRICE_FALLBACK
        name = p["name"] if p else f"Item {item['pid']}"
        line_total = price * item["qty"]
        subtotal += line_total
        out.append({"pid": item["pid"], "name": name,
                    "flavor": p["flavor"] if p else "", "price": price,
                    "qty": item["qty"], "line_total": round(line_total, 2)})
    return out, round(subtotal, 2)
