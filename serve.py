#!/usr/bin/env python3
"""App container entrypoint. Serves the storefront only.

There is no second port and no scoring API here: the scorer is a separate
container, and this process has no route to it beyond the one-way tap socket.
"""
from waitress import serve
from app import create_app, config


def main():
    app = create_app()
    print(f" * SPRKL storefront : http://0.0.0.0:{config.APP_PORT}", flush=True)
    # Keep X-Forwarded-* intact: the app deliberately trusts them (rate-limit
    # bypass, log spoofing, cache poisoning via X-Forwarded-Host all depend on it).
    # Waitress otherwise strips them (clear_untrusted_proxy_headers defaults True).
    serve(app, host="0.0.0.0", port=config.APP_PORT, threads=16, _quiet=True,
          clear_untrusted_proxy_headers=False)


if __name__ == "__main__":
    main()
