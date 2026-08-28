"""Minimal GraphQL endpoint (regex-parsed, no external lib).

Supports just enough to host four findings:
  - graphql-introspection : __schema leaks a hidden type carrying a canary
  - graphql-bola          : user(id:) resolver ignores ownership
  - graphql-sql-injection : product(slug:) builds SQL from the argument
  - graphql-batching-dos  : no depth/alias limit -> disproportionate work
"""
import re, sqlite3
from flask import Blueprint, request, jsonify
from ... import db
from ...util import actor as session_actor
from ...oracle import engine

bp = Blueprint("graphql", __name__)

HIDDEN_CANARY = "SPRKL-CANARY-GRAPHQL-HIDDEN"
engine.register_canary(HIDDEN_CANARY, owner="system", kind="graphql-hidden")

SCHEMA = {
    "types": ["Product", "User", "Order",
              {"name": "InternalConfig", "fields": ["apiKey"], "note": HIDDEN_CANARY}],
}


@bp.route("/graphql", methods=["POST", "GET"])
def graphql():
    actor = session_actor()
    body = request.get_json(silent=True) or {}
    query = body.get("query") or request.args.get("query", "")

    # introspection
    if "__schema" in query or "__type" in query:
        engine.leaked_canary("graphql-introspection", actor, str(SCHEMA))
        return jsonify({"data": {"__schema": SCHEMA}})

    # batching / depth abuse
    aliases = len(re.findall(r"\w+\s*:", query))
    depth = query.count("{")
    if aliases >= 20 or depth >= 12:
        # simulate the disproportionate work an unbounded resolver would do
        total = sum(1 for _ in range(aliases * depth * 1000))
        engine.solve("graphql-batching-dos", actor,
                     {"aliases": aliases, "depth": depth, "work": total})
        return jsonify({"data": {}, "note": "processed"})

    data = {}
    # user(id: N)
    m = re.search(r"user\s*\(\s*id\s*:\s*(\d+)\s*\)", query)
    if m:
        uid = int(m.group(1))
        row = db.query("SELECT id,email,name,secret FROM users WHERE id=?", (uid,), one=True)
        if row:
            data["user"] = dict(row)
            if actor != f"user:{uid}":
                engine.leaked_canary("graphql-bola", actor, str(dict(row)))

    # product(slug: "X")  -> VULN sql injection
    m = re.search(r'product\s*\(\s*slug\s*:\s*"([^"]*)"\s*\)', query)
    if m:
        slug = m.group(1)
        sql = "SELECT id,name,flavor FROM products WHERE slug='" + slug + "'"
        try:
            rows = db.raw_query(sql)
            data["product"] = [dict(r) for r in rows]
            engine.leaked_canary("graphql-sql-injection", actor, str([tuple(r) for r in rows]))
        except sqlite3.Error as e:
            return jsonify({"errors": [{"message": str(e)}]}), 400

    return jsonify({"data": data})
