#!/usr/bin/env python3
"""Launch SPRKL: the attackable storefront + the separate-port oracle scoring API."""
import threading
from app import create_app, config
from app.oracle.api import create_oracle_app


def _serve(app, port):
    app.run(host="0.0.0.0", port=port, threaded=True, use_reloader=False)


def main():
    app = create_app()
    oracle_app = create_oracle_app()

    t = threading.Thread(target=_serve, args=(oracle_app, config.ORACLE_PORT), daemon=True)
    t.start()
    print(f" * SPRKL storefront  : http://127.0.0.1:{config.APP_PORT}")
    print(f" * SPRKL oracle (key): http://127.0.0.1:{config.ORACLE_PORT}  "
          f"(X-Oracle-Key: {config.ORACLE_KEY})")
    _serve(app, config.APP_PORT)


if __name__ == "__main__":
    main()
