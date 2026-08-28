"""Seed SPRKL with a believable storefront + planted canary secrets.

Canary tokens are the ground-truth markers for `canary`-type findings: if one
of these strings reaches an unauthorized actor through a vulnerability, the
oracle fires. They live in DB columns that legitimate flows never expose.
"""
import hashlib
from . import db
from .oracle import engine
from .backends import nosql, ldap, objstore

CANARY = "SPRKL-CANARY-{}"


def metadata_secret():
    from .backends import metadata
    return metadata.CREDS["SecretAccessKey"]


def _md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def seed():
    db.init_schema()
    conn = db.get_db()
    # idempotent: only seed an empty store
    if db.query("SELECT COUNT(*) c FROM users", one=True)["c"]:
        _register_canaries()
        return

    users = [
        # id, email, password, name, role, org_id, address, loyalty
        (1, "alice@example.com", "password1", "Alice Retail", "customer", None,
         "12 Fizz Lane", 120),
        (2, "bob@example.com", "hunter2", "Bob Bubbles", "customer", None,
         "9 Seltzer St", 40),
        (3, "carol@sprkl-corp.com", "Spring2024!", "Carol Corp", "buyer", 100,
         "1 Corporate Way", 0),
        (4, "dave@rival-corp.com", "Rival2024!", "Dave Rival", "buyer", 200,
         "5 Rival Rd", 0),
        (5, "admin@sprkl-corp.com", "admin", "SPRKL Admin", "admin", 100,
         "HQ", 0),
    ]
    for (uid, email, pw, name, role, org, addr, loy) in users:
        secret = CANARY.format(f"USER-{uid}")
        db.execute(
            "INSERT INTO users (id,email,password,pw_md5,name,role,org_id,address,loyalty,secret)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (uid, email, pw, _md5(pw), name, role, org, addr, loy, secret),
        )

    products = [
        ("classic", "SPRKL Classic", "Original", 3.50),
        ("lime", "SPRKL Lime Twist", "Lime", 3.75),
        ("berry", "SPRKL Wild Berry", "Berry", 3.95),
        ("grapefruit", "SPRKL Grapefruit", "Grapefruit", 3.75),
        ("cola", "SPRKL Cola Fizz", "Cola", 4.25),
    ]
    for i, (slug, name, flavor, price) in enumerate(products, 1):
        secret = CANARY.format(f"PROD-{i}")
        spec = (f"<spec><flavor>{flavor}</flavor><carbonation>high</carbonation>"
                f"<internal>{secret}</internal></spec>")
        db.execute(
            "INSERT INTO products (id,slug,name,flavor,price,in_stock,listed,spec_xml,secret)"
            " VALUES (?,?,?,?,?,1,1,?,?)",
            (i, slug, name, flavor, price, spec, secret),
        )
    # an UNLISTED product (only reachable via unrestricted resource / SQLi)
    db.execute(
        "INSERT INTO products (id,slug,name,flavor,price,in_stock,listed,spec_xml,secret)"
        " VALUES (99,'proto-x','SPRKL Prototype X','Secret',9.99,1,0,'<spec/>',?)",
        (CANARY.format("PROD-UNLISTED"),),
    )

    orders = [
        (1001, 1, 42.0, "delivered", "SP-AAA111"),
        (1002, 2, 18.5, "shipped", "SP-BBB222"),
        (1003, 3, 980.0, "processing", "SP-CCC333"),   # org 100
        (1004, 4, 1200.0, "processing", "SP-DDD444"),   # org 200
    ]
    for (oid, uid, total, status, ref) in orders:
        db.execute(
            "INSERT INTO orders (id,user_id,total,status,ref,secret) VALUES (?,?,?,?,?,?)",
            (oid, uid, total, status, ref, CANARY.format(f"ORDER-{oid}")),
        )

    coupons = [
        ("WELCOME10", "percent", "10", 0),
        ("ONCE20", "percent", "20", 0),          # meant to be single-use
        ("FORMULA", "formula", "min(50, subtotal*0.15)", 0),  # eval'd -> code injection
    ]
    for (code, kind, value, used) in coupons:
        db.execute("INSERT INTO coupons (code,kind,value,used) VALUES (?,?,?,?)",
                   (code, kind, value, used))

    # gift cards (canary codes), wallet, referrals
    db.execute("INSERT INTO giftcards (id,owner_id,code,balance,secret) VALUES (?,?,?,?,?)",
               (1, 1, "GC-ALICE-1", 50.0, CANARY.format("GC-1")))
    db.execute("INSERT INTO giftcards (id,owner_id,code,balance,secret) VALUES (?,?,?,?,?)",
               (2, 2, "GC-BOB-2", 25.0, CANARY.format("GC-2")))
    db.execute("INSERT INTO wallet (user_id,balance) VALUES (1,10.0)")
    db.execute("INSERT INTO wallet (user_id,balance) VALUES (2,0.0)")
    db.execute("INSERT INTO referrals (id,code,owner_id,redeemed_by) VALUES (1,'REF-ALICE',1,NULL)")
    db.execute("INSERT INTO referrals (id,code,owner_id,redeemed_by) VALUES (2,'REF-CAROL',3,NULL)")
    db.execute("INSERT INTO wishlists (id,user_id,item,secret) VALUES (1,1,'SPRKL Lime Twist',?)",
               (CANARY.format("WISH-1"),))
    db.execute("INSERT INTO wishlists (id,user_id,item,secret) VALUES (2,2,'SPRKL Cola Fizz',?)",
               (CANARY.format("WISH-2"),))
    db.execute("INSERT INTO flags (name,value) VALUES ('maintenance','off')")
    db.execute("INSERT INTO flags (name,value) VALUES ('beta_pricing','off')")
    # canary file for XXE / path-traversal to read
    import os as _os
    _os.makedirs(db.config.DATA_DIR, exist_ok=True) if hasattr(db, "config") else None
    conn.commit()

    from . import config as _cfg
    _os.makedirs(_cfg.DATA_DIR, exist_ok=True)
    with open(_os.path.join(_cfg.DATA_DIR, "flag.txt"), "w") as _fh:
        _fh.write(CANARY.format("XXE-FILE"))

    # ---- backend fakes ----
    nosql.seed("corp_users", [
        {"username": "carol", "password": "Spring2024!", "org": 100, "role": "buyer"},
        {"username": "admin", "password": "admin", "org": 100, "role": "admin",
         "secret": CANARY.format("CORP-ADMIN")},
    ])
    nosql.seed("newsletter", [
        {"email": "alice@example.com", "topic": "flavors", "secret": CANARY.format("NL-1")},
        {"email": "vip@sprkl-corp.com", "topic": "wholesale", "secret": CANARY.format("NL-2")},
    ])
    ldap.seed([
        {"uid": "carol", "cn": "Carol Corp", "title": "Buyer", "org": "100"},
        {"uid": "admin", "cn": "SPRKL Admin", "title": "Administrator",
         "org": "100", "secret": CANARY.format("LDAP-ADMIN")},
    ])
    objstore.put("logo.png", b"PNG...", private=False)
    objstore.put("brochure.pdf", b"PDF...", private=False)
    objstore.put("private/payroll-2024.csv", CANARY.format("BUCKET-PAYROLL"), private=True)
    _register_canaries()


def _register_canaries():
    """Load every planted canary into the oracle's in-memory registry."""
    for r in db.query("SELECT id, secret FROM users"):
        engine.register_canary(r["secret"], owner=f"user:{r['id']}", kind="user-secret")
    for r in db.query("SELECT id, secret FROM products WHERE secret IS NOT NULL"):
        engine.register_canary(r["secret"], owner="system", kind="product-secret")
    for r in db.query("SELECT id, user_id, secret FROM orders"):
        engine.register_canary(r["secret"], owner=f"user:{r['user_id']}", kind="order-secret")
    for r in db.query("SELECT owner_id, secret FROM giftcards"):
        engine.register_canary(r["secret"], owner=f"user:{r['owner_id']}", kind="giftcard-secret")
    for r in db.query("SELECT user_id, secret FROM wishlists"):
        engine.register_canary(r["secret"], owner=f"user:{r['user_id']}", kind="wishlist-secret")
    # backend + file canaries owned by 'system' (any non-owner leak counts)
    for tok in ["CORP-ADMIN", "NL-1", "NL-2", "LDAP-ADMIN", "BUCKET-PAYROLL",
                "ENV-SECRET", "DEBUG-SECRET", "JSKEY"]:
        engine.register_canary(CANARY.format(tok), owner="system", kind="planted")
    engine.register_canary("SPRKL-CANARY-JSKEY-9c1f2a", owner="system", kind="js-key")
    engine.register_canary(CANARY.format("XXE-FILE"), owner="system", kind="xxe-file")
    engine.register_canary(metadata_secret(), owner="system", kind="iam")
