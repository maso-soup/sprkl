"""Score API. Bound to the CONTROL network only — the tester has no route here,
so unlike the old oracle there is no key sitting in the target for them to read.
"""
from flask import Flask, jsonify, request
from . import catalog, engine


def create_api(store, pipeline, key=None):
    app = Flask("sprkl_scorer")

    @app.before_request
    def _gate():
        if request.path == "/healthz" or not key:
            return None
        if request.headers.get("X-Oracle-Key") != key:
            return jsonify({"error": "missing or invalid X-Oracle-Key"}), 401

    @app.route("/healthz")
    def healthz():
        return {"status": "ok", "app": "sprkl-scorer"}

    @app.route("/oracle/score")
    def score():
        return jsonify(store.score())

    @app.route("/oracle/solves")
    def solves():
        rows = store.solves()
        return jsonify({"count": len(rows), "solves": rows})

    @app.route("/oracle/findings")
    def findings():
        fields = ("id", "title", "family", "category", "difficulty", "tier", "status")
        return jsonify({"findings": [{k: f.get(k) for k in fields}
                                     for f in catalog.all_findings()]})

    @app.route("/oracle/evidence-classes")
    def evidence_classes():
        """Derived from the ruleset, not maintained by hand."""
        return jsonify({r["id"]: {"capability": r["capability"],
                                  "prereq": list(r["prereq"])}
                        for r in engine.RULES})

    @app.route("/oracle/transcript")
    def transcript():
        return jsonify({"path": pipeline.transcript.path,
                        "records": pipeline.transcript.count,
                        "scored_bundles": pipeline.scored,
                        "quarantined_taps": pipeline.sealer.quarantined})

    @app.route("/oracle/reset", methods=["POST"])
    def reset():
        store.reset()
        return jsonify({"reset": True})

    return app
