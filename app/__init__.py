"""SPRKL app factory.

This process contains no scoring logic, no findings catalog, no scoring key and
no solve store. It reports what it did over a one-way tap and is told nothing
about what any of it means.
"""
from datetime import timedelta
from flask import Flask, request, session, jsonify, redirect, url_for, Response
from . import config, db, seed, tap


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = config.FLASK_SECRET
    app.permanent_session_lifetime = timedelta(days=7)

    tap.install(app)

    with app.app_context():
        seed.seed()

    @app.before_request
    def _persist_session():
        # Sessions persist until logout (like a normal web app).
        session.permanent = True

    # Make auth state + cart available to every template.
    @app.context_processor
    def _inject_ctx():
        user = None
        if session.get("uid"):
            user = db.query(
                "SELECT id,name,email,loyalty,role FROM users WHERE id=?",
                (session["uid"],), one=True)
        cart = session.get("cart", [])
        return {
            "current_user": user,
            "current_admin": session.get("admin"),
            "current_admin_role": session.get("admin_role"),
            "cart_count": sum(int(i.get("qty", 0)) for i in cart),
        }

    from .tiers.public.routes import bp as public_bp
    from .tiers.retail.routes import bp as retail_bp
    from .api.rest.routes import bp as api_rest_bp
    from .api.graphql.routes import bp as graphql_bp
    from .extras import bp as extras_bp
    from .tiers.admin.routes import bp as admin_bp
    for b in (public_bp, retail_bp, api_rest_bp, graphql_bp, extras_bp, admin_bp):
        app.register_blueprint(b)

    # ---- session lifecycle ----
    @app.route("/logout", methods=["GET", "POST"])
    @app.route("/retail/logout", methods=["GET", "POST"])
    def logout():
        session.clear()
        return redirect(url_for("public.home"))

    @app.route("/admin/logout", methods=["GET", "POST"])
    def admin_logout():
        session.pop("admin", None)
        session.pop("admin_role", None)
        session.pop("pre_mfa", None)
        return redirect("/admin")

    # ---- recon artifacts (deliberately does NOT mention /admin) ----
    @app.route("/robots.txt")
    def robots():
        body = ("User-agent: *\n"
                "Disallow: /debug\n"
                "Disallow: /backup.zip\n"
                "Disallow: /.env\n"
                "Disallow: /assets/\n"
                "Disallow: /api/v1/\n")
        return Response(body, mimetype="text/plain")

    @app.route("/sitemap.xml")
    def sitemap():
        urls = ["/", "/products", "/search", "/support", "/status",
                "/store-locator", "/retail/login"]
        items = "".join(f"<url><loc>{u}</loc></url>" for u in urls)
        xml = f'<?xml version="1.0" encoding="UTF-8"?><urlset>{items}</urlset>'
        return Response(xml, mimetype="application/xml")

    # The promo key is a per-run value embedded in the storefront JS. Serve app.js
    # with the run's value injected so reading it and submitting it to
    # /api/v2/keycheck validates; the file on disk holds only a placeholder.
    import pathlib as _pathlib
    _APP_JS = _pathlib.Path(app.static_folder) / "app.js"

    @app.route("/static/app.js")
    def _serve_app_js():
        js = _APP_JS.read_text().replace(
            "__PROMO_KEY__", config.SPEC.get("assets", {}).get("jskey", ""))
        return Response(js, mimetype="application/javascript")

    @app.route("/healthz")
    def healthz():
        return {"status": "ok", "app": "sprkl"}

    return app
