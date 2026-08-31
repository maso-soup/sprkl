#!/usr/bin/env python3
"""Scorer container entrypoint.

Owns: the ingress proxy the tester talks to, the one-way tap intake, the OAST
collector, the transcript, the rules, the solve store, and the score API.

The app container is handed nothing but values. It has no catalog, no rules, no
key, no solve store, and no route to this process's filesystem.
"""
import asyncio, json, os, secrets, threading, time
from shared import records as R
from . import api, ingest, seedgen, store as store_mod
from . import rules as _rules       # noqa: F401 - registers the ruleset

LISTEN_HOST = os.environ.get("SPRKL_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("SPRKL_LISTEN_PORT", "8080"))
UPSTREAM_HOST = os.environ.get("SPRKL_UPSTREAM_HOST", "app")
UPSTREAM_PORT = int(os.environ.get("SPRKL_UPSTREAM_PORT", "8081"))
API_PORT = int(os.environ.get("SPRKL_API_PORT", "9090"))
API_HOST = os.environ.get("SPRKL_API_HOST", "0.0.0.0")
COLLAB_PORT = int(os.environ.get("SPRKL_COLLAB_PORT", "8088"))
TAP_SOCKET = os.environ.get("SPRKL_TAP_SOCKET", "/run/sprkl/tap.sock")
SEED_FILE = os.environ.get("SPRKL_SEED_FILE", "/run/sprkl/seed.json")
RUNS_DIR = os.environ.get("SPRKL_RUNS", "/runs")
API_KEY = os.environ.get("SPRKL_ORACLE_KEY") or None


def _rid_factory():
    counter = [0]
    boot = secrets.token_hex(4)
    def rid():
        counter[0] += 1
        return f"{boot}-{counter[0]:08d}"
    return rid


async def collab_server(pipeline, port):
    """OAST collector. A real external service now, not 127.0.0.1 inside the app."""
    async def handle(reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        except Exception:
            writer.close(); return
        line = head.split(b"\r\n")[0].decode("latin-1", "replace")
        parts = line.split(" ")
        method, target = (parts + ["", ""])[:2]
        peer = writer.get_extra_info("peername") or ("?", 0)
        ua = ""
        for h in head.split(b"\r\n")[1:]:
            if h.lower().startswith(b"user-agent:"):
                ua = h.split(b":", 1)[1].strip().decode("latin-1", "replace")
        token = target.rsplit("/", 1)[-1].split("?")[0]
        pipeline.feed(R.oast(token, peer[0], method, target, ua))
        body = b'{"collab":"ok"}'
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     b"Content-Length: " + str(len(body)).encode() +
                     b"\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()

    return await asyncio.start_server(handle, "0.0.0.0", port)


async def amain():
    from .proxy import Proxy

    run = seedgen.generate()
    os.makedirs(os.path.dirname(SEED_FILE), exist_ok=True)
    tmp = SEED_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(run["spec"], fh)
    os.replace(tmp, SEED_FILE)

    run_dir = os.path.join(RUNS_DIR, run["run"])
    blobs = R.BlobStore(os.path.join(run_dir, "blobs"))
    transcript = ingest.Transcript(os.path.join(run_dir, "transcript.jsonl"))
    store = store_mod.Store(os.path.join(run_dir, "solves.db"))

    manifest_rec = R.manifest(
        run=run["run"], app={"image": os.environ.get("SPRKL_APP_IMAGE", "?")},
        seed=run["run"], canaries=run["manifest"]["canaries"],
        accounts=run["manifest"]["accounts"], secrets=run["manifest"]["secrets"],
        internal_cidrs=run["manifest"]["internal_cidrs"],
        canary_prefix=run["manifest"]["canary_prefix"])

    pipeline = ingest.Pipeline(transcript, store, manifest_rec)
    pipeline.feed(manifest_rec)
    pipeline.feed(R.run_marker("start"))

    proxy = Proxy(UPSTREAM_HOST, UPSTREAM_PORT, pipeline.feed, _rid_factory(), blobs)
    servers = [
        await proxy.serve(LISTEN_HOST, LISTEN_PORT),
        await ingest.tap_server(TAP_SOCKET, pipeline),
        await collab_server(pipeline, COLLAB_PORT),
    ]

    flask_app = api.create_api(store, pipeline, API_KEY)
    threading.Thread(
        target=lambda: __import__("waitress").serve(
            flask_app, host=API_HOST, port=API_PORT, threads=4, _quiet=True),
        daemon=True).start()

    print(f" * run          : {run['run']}")
    print(f" * ingress      : http://{LISTEN_HOST}:{LISTEN_PORT} -> "
          f"{UPSTREAM_HOST}:{UPSTREAM_PORT}")
    print(f" * score api    : http://{API_HOST}:{API_PORT} (control network)")
    print(f" * transcript   : {transcript.path}", flush=True)

    await asyncio.gather(ingest.ticker(pipeline),
                         *[s.serve_forever() for s in servers])


def main():
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
