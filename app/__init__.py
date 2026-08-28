"""SPRKL app factory. Builds the attackable storefront (main app) and mounts the
internal OAST collab collector. The scoring API is a SEPARATE app (oracle/api.py)."""
from flask import Flask, request, jsonify
from . import config, db, seed
from .oracle import collab


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = config.FLASK_SECRET  # VULN: guessable session secret

    with app.app_context():
        seed.seed()

    from .tiers.public.routes import bp as public_bp
    from .tiers.retail.routes import bp as retail_bp
    from .tiers.corporate.routes import bp as corporate_bp
    from .api.rest.routes import bp as api_rest_bp
    from .api.graphql.routes import bp as graphql_bp
    from .extras import bp as extras_bp
    app.register_blueprint(public_bp)
    app.register_blueprint(retail_bp)
    app.register_blueprint(corporate_bp)
    app.register_blueprint(api_rest_bp)
    app.register_blueprint(graphql_bp)
    app.register_blueprint(extras_bp)

    # Internal OAST collector. Reachable at /collab/<token> so injected payloads
    # (blind cmd inj, SSRF, blind XSS) can call back and prove execution.
    @app.route("/collab/<path:token>", methods=["GET", "POST"])
    def collab_hit(token):
        fid = collab.hit(token, {"ip": request.remote_addr,
                                 "ua": request.headers.get("User-Agent", "")})
        return jsonify({"collab": "ok", "matched": bool(fid)})

    @app.route("/healthz")
    def healthz():
        return {"status": "ok", "app": "sprkl"}

    return app
