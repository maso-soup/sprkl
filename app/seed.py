"""Seed the storefront from the run spec the scorer published.

Every planted secret is a value handed to us. This module does not know which
of them are markers, who owns them, or what leaking one would mean — that map
lives in the scorer's manifest, so an RCE here cannot enumerate it.
"""
import hashlib, os
from . import config, db
from .backends import nosql, ldap, objstore

SPEC = config.SPEC


def _md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def seed():
    db.init_schema()
    conn = db.get_db()
    if db.query("SELECT COUNT(*) c FROM users", one=True)["c"]:
        return

    for u in SPEC["users"]:
        db.execute(
            "INSERT INTO users (id,email,password,pw_md5,name,role,org_id,address,loyalty,secret)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (u["id"], u["email"], u["password"], _md5(u["password"]), u["name"],
             u["role"], u["org_id"], u["address"], u["loyalty"], u["secret"]))

    for p in SPEC["products"]:
        spec_xml = (f"<spec><flavor>{p['flavor']}</flavor>"
                    f"<carbonation>high</carbonation>"
                    f"<internal>{p['secret']}</internal></spec>")
        db.execute(
            "INSERT INTO products (id,slug,name,flavor,price,in_stock,listed,spec_xml,secret)"
            " VALUES (?,?,?,?,?,1,?,?,?)",
            (p["id"], p["slug"], p["name"], p["flavor"], p["price"],
             p["listed"], spec_xml, p["secret"]))

    for o in SPEC["orders"]:
        db.execute(
            "INSERT INTO orders (id,user_id,total,status,ref,secret) VALUES (?,?,?,?,?,?)",
            (o["id"], o["user_id"], o["total"], o["status"], o["ref"], o["secret"]))

    for c in SPEC["coupons"]:
        db.execute("INSERT INTO coupons (code,kind,value,used) VALUES (?,?,?,?)",
                   (c["code"], c["kind"], c["value"], c["used"]))

    for g in SPEC["giftcards"]:
        db.execute("INSERT INTO giftcards (id,owner_id,code,balance,secret) VALUES (?,?,?,?,?)",
                   (g["id"], g["owner_id"], g["code"], g["balance"], g["secret"]))

    for w in SPEC["wishlists"]:
        db.execute("INSERT INTO wishlists (id,user_id,item,secret) VALUES (?,?,?,?)",
                   (w["id"], w["user_id"], w["item"], w["secret"]))

    db.execute("INSERT INTO wallet (user_id,balance) VALUES (1,10.0)")
    db.execute("INSERT INTO wallet (user_id,balance) VALUES (2,0.0)")
    db.execute("INSERT INTO referrals (id,code,owner_id,redeemed_by) VALUES (1,'REF-ALICE',1,NULL)")
    db.execute("INSERT INTO referrals (id,code,owner_id,redeemed_by) VALUES (2,'REF-CAROL',3,NULL)")
    db.execute("INSERT INTO flags (name,value) VALUES ('maintenance','off')")
    db.execute("INSERT INTO flags (name,value) VALUES ('beta_pricing','off')")
    conn.commit()

    os.makedirs(config.DATA_DIR, exist_ok=True)
    with open(os.path.join(config.DATA_DIR, "flag.txt"), "w") as fh:
        fh.write(SPEC["planted"]["xxe_file"])

    for name, docs in SPEC["nosql"].items():
        nosql.seed(name, docs)
    ldap.seed(SPEC["ldap"])
    for obj in SPEC["objstore"]:
        objstore.put(obj["key"], obj["body"], private=obj["private"])
