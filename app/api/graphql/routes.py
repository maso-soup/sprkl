"""Minimal GraphQL endpoint (regex-parsed, no external lib)."""
import re, sqlite3
from flask import Blueprint, request, jsonify
from ... import config, db, tap
from ...util import actor as session_actor

bp = Blueprint("graphql", __name__)

HIDDEN_CANARY = config.SPEC.get("planted", {}).get("graphql_hidden", "")

SCHEMA = {
    "types": ["Product", "User", "Order",
              {"name": "InternalConfig", "fields": ["apiKey"], "note": HIDDEN_CANARY}],
}


@bp.route("/graphql", methods=["POST", "GET"])
def graphql():
    actor = session_actor()
    body = request.get_json(silent=True) or {}
    query = body.get("query") or request.args.get("query", "")

    if "__schema" in query or "__type" in query:
        return jsonify({"data": {"__schema": SCHEMA}})

    aliases = len(re.findall(r"\w+\s*:", query))
    depth = query.count("{")
    tap.emit("obj.assign", target="graphql.query", aliases=aliases, depth=depth)
    if aliases >= 20 or depth >= 12:
        # no depth or alias limit: the resolver does the work it is asked for
        total = sum(1 for _ in range(aliases * depth * 1000))
        return jsonify({"data": {}, "note": "processed", "resolved": total})

    data = {}
    # user(id: N)
    m = re.search(r"user\s*\(\s*id\s*:\s*(\d+)\s*\)", query)
    if m:
        uid = int(m.group(1))
        row = db.query("SELECT id,email,name,secret FROM users WHERE id=?", (uid,), one=True)
        if row:
            data["user"] = dict(row)

    m = re.search(r'product\s*\(\s*slug\s*:\s*"([^"]*)"\s*\)', query)
    if m:
        slug = m.group(1)
        sql = "SELECT id,name,flavor FROM products WHERE slug='" + slug + "'"
        try:
            data["product"] = [dict(r) for r in db.query(sql, None)]
        except sqlite3.Error as e:
            return jsonify({"errors": [{"message": str(e)}]}), 400

    return jsonify({"data": data})
