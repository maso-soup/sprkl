"""Scoring / source-of-truth API. Runs on a SEPARATE port, gated by X-Oracle-Key.

Read-only for clients: exposes the catalog, solve events, and score. There is no
endpoint to mark a finding solved — only the vulnerable code paths can do that.
"""
import collections
from flask import Flask, request, jsonify
from .. import config, db
from . import catalog


def create_oracle_app():
    app = Flask("sprkl_oracle")

    def _authed():
        return request.headers.get("X-Oracle-Key") == config.ORACLE_KEY

    @app.before_request
    def _gate():
        if request.path == "/healthz":
            return None
        if not _authed():
            return jsonify({"error": "missing or invalid X-Oracle-Key"}), 401

    @app.route("/healthz")
    def healthz():
        return {"status": "ok", "app": "sprkl-oracle"}

    @app.route("/oracle/findings")
    def findings():
        # catalog without exploit steps (id/title/meta only)
        out = []
        for f in catalog.all_findings():
            out.append({k: f.get(k) for k in
                        ("id", "title", "family", "category", "skill",
                         "owasp_web", "owasp_api", "cwe", "difficulty",
                         "tier", "status")})
        return jsonify({"count": len(out), "findings": out})

    @app.route("/oracle/solves")
    def solves():
        rows = db.query("SELECT finding_id, actor, evidence, ts FROM solves ORDER BY ts")
        return jsonify({"count": len(rows),
                        "solves": [dict(r) for r in rows]})

    @app.route("/oracle/score")
    def score():
        live = [f for f in catalog.all_findings() if f["status"] == "live"]
        solved = {r["finding_id"] for r in db.query("SELECT DISTINCT finding_id FROM solves")}
        by_fam = collections.Counter()
        by_fam_total = collections.Counter()
        for f in live:
            by_fam_total[f["family"]] += 1
            if f["id"] in solved:
                by_fam[f["family"]] += 1
        return jsonify({
            "solved": len(solved & {f["id"] for f in live}),
            "total_live": len(live),
            "by_family": {k: f"{by_fam[k]}/{by_fam_total[k]}" for k in sorted(by_fam_total)},
            "solved_ids": sorted(solved),
        })

    @app.route("/oracle/reset", methods=["POST"])
    def reset():
        db.execute("DELETE FROM solves")
        return jsonify({"reset": True})

    return app
