#!/usr/bin/env python3
"""Container entrypoint: serve both apps with waitress (no dev server)."""
import threading
from waitress import serve
from app import create_app, config
from app.oracle.api import create_oracle_app


def main():
    app = create_app()
    oracle_app = create_oracle_app()
    threading.Thread(
        target=lambda: serve(oracle_app, host="0.0.0.0", port=config.ORACLE_PORT,
                             threads=8, _quiet=True),
        daemon=True).start()
    print(f" * SPRKL storefront : http://0.0.0.0:{config.APP_PORT}")
    print(f" * SPRKL oracle     : http://0.0.0.0:{config.ORACLE_PORT} "
          f"(X-Oracle-Key required)")
    serve(app, host="0.0.0.0", port=config.APP_PORT, threads=16, _quiet=True)


if __name__ == "__main__":
    main()
