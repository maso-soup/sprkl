"""In-process launcher for local runs and tests: app subprocess + proxy + scorer,
no Docker. Returns the ingress base URL and the live store so a test can drive
real HTTP exploits and read ground truth, exactly as the two-container deploy does.
"""
import asyncio, json, os, socket, subprocess, tempfile, threading, time
from shared import records as R
from . import ingest, seedgen, store as store_mod, proxy as proxymod
from . import rules as _rules  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Harness:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="sprkl-harness-")
        self.app_port = _free_port()
        self.proxy_port = _free_port()
        self.collab_port = _free_port()
        self.base = f"http://127.0.0.1:{self.proxy_port}"
        self._loop = None
        self._proc = None

    def start(self):
        run = seedgen.generate()
        seed_file = os.path.join(self.tmp, "seed.json")
        json.dump(run["spec"], open(seed_file, "w"))
        tap_sock = os.path.join(self.tmp, "tap.sock")
        run_dir = os.path.join(self.tmp, "run")
        os.makedirs(run_dir)

        m = run["manifest"]
        manifest = R.manifest(run=m["run"], app={"image": "harness"}, seed=m["run"],
            canaries=m["canaries"], accounts=m["accounts"], secrets=m["secrets"],
            internal_cidrs=m["internal_cidrs"], canary_prefix=m["canary_prefix"])
        self.blobs = R.BlobStore(os.path.join(run_dir, "blobs"))
        self.transcript = ingest.Transcript(os.path.join(run_dir, "transcript.jsonl"))
        self.store = store_mod.Store(os.path.join(run_dir, "solves.db"))
        self.pipeline = ingest.Pipeline(self.transcript, self.store, manifest, grace=0.05)
        self.pipeline.feed(manifest)

        env = dict(os.environ, SPRKL_APP_PORT=str(self.app_port),
                   SPRKL_DATA=os.path.join(self.tmp, "data"), SPRKL_SEED_FILE=seed_file,
                   SPRKL_TAP_SOCKET=tap_sock,
                   SPRKL_COLLAB_BASE=f"http://127.0.0.1:{self.collab_port}/c")
        py = os.path.join(ROOT, ".venv", "bin", "python")
        py = py if os.path.exists(py) else "python3"
        self._proc = subprocess.Popen([py, "serve.py"], cwd=ROOT, env=env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._wait(self.app_port)

        n = [0]
        def rid():
            n[0] += 1
            return f"h-{n[0]:08d}"

        ready = threading.Event()

        def run_loop():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            proxy = proxymod.Proxy("127.0.0.1", self.app_port,
                                   self._feed_threadsafe, rid, self.blobs)

            async def boot():
                self._server = await proxy.serve("127.0.0.1", self.proxy_port)
                self._tap = await ingest.tap_server(tap_sock, self.pipeline)
                asyncio.create_task(ingest.ticker(self.pipeline, 0.05))
                ready.set()
            self._loop.run_until_complete(boot())
            self._loop.run_forever()

        self._thread = threading.Thread(target=run_loop, daemon=True)
        self._thread.start()
        ready.wait(10)
        self._wait(self.proxy_port)
        return self

    def _feed_threadsafe(self, rec):
        self._loop.call_soon_threadsafe(self.pipeline.feed, rec)

    def settle(self, seconds=0.6):
        """Let the grace window elapse so all bundles seal before reading solves."""
        time.sleep(seconds)
        fut = asyncio.run_coroutine_threadsafe(self._drain(), self._loop)
        fut.result(5)

    async def _drain(self):
        self.pipeline.tick()
        self.pipeline.drain()

    def solved(self):
        self.settle(0.0)
        return set(self.store.score()["solved_ids"])

    def score(self):
        self.settle(0.0)
        return self.store.score()

    def _wait(self, port, t=15):
        end = time.time() + t
        while time.time() < end:
            try:
                with socket.create_connection(("127.0.0.1", port), 0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"port {port} never came up")

    def stop(self):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._loop:
            async def _shutdown():
                for t in asyncio.all_tasks(self._loop):
                    if t is not asyncio.current_task():
                        t.cancel()
            try:
                fut = asyncio.run_coroutine_threadsafe(_shutdown(), self._loop)
                fut.result(2)
            except Exception:
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)
