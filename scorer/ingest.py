"""Transcript writer, tap intake, and the scoring pipeline."""
import asyncio, json, os, time
from shared import records as R
from . import engine
from .record import Record


class Transcript:
    """Append-only JSONL. The canonical artifact: (transcript, rules) -> solves."""

    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.fh = open(path, "a", buffering=1)
        self.path = path
        self.count = 0

    def write(self, rec):
        self.fh.write(R.dumps(rec) + "\n")
        self.count += 1

    def close(self):
        try:
            self.fh.close()
        except Exception:
            pass


class Pipeline:
    """Owns the sealer, the store, and rule evaluation."""

    def __init__(self, transcript, store, manifest, grace=0.5):
        self.transcript = transcript
        self.store = store
        self.manifest = manifest
        self.sealer = R.Sealer(grace=grace)
        self.state = {}
        self.scored = 0

    def feed(self, rec, record_to_transcript=True):
        try:
            R.validate(rec)
        except R.BadRecord:
            return
        if record_to_transcript:
            self.transcript.write(rec)
        for kind, payload in self.sealer.add(rec):
            if kind in ("seal", "reseal"):
                self.score(payload)
            elif kind == "standalone" and payload["t"] == "oast":
                self.store.record_oast(payload["token"], None,
                                       payload["ts"], payload.get("src_ip"))

    def tick(self, now=None):
        for kind, bundle in self.sealer.tick(now):
            self.score(bundle)

    def drain(self):
        for kind, bundle in self.sealer.drain():
            self.score(bundle)

    def score(self, bundle):
        rec = Record(bundle, self.manifest, self.store, self.state)
        actor = rec.actor
        ts = rec.ts

        # Persisted attacker input, taken from the PROXY-observed request body so
        # the stored-content rules match on what was submitted, not page chrome.
        path = bundle["ingress"]["req"]["path"]
        if path.endswith("/review") or path == "/contact":
            for v in list(rec.form.values()) + list(rec.args.values()):
                self.store.remember_stored("html", v, actor, ts)

        # Earn principals BEFORE rules run: a login that legitimately succeeded
        # in this very request must count, or the actor gets credited with
        # leaking a secret they had just been granted.
        for e in bundle["events"]:
            if e["t"] == "tap" and e["k"] == "auth.result":
                d = e["d"]
                if d.get("ok") and d.get("password_verified") and d.get("principal"):
                    self.store.earn_principal(actor, d["principal"], ts)
        rec.touched.clear()

        for r, touched in engine.evaluate(rec):
            self.store.solve(
                finding_id=r["id"], actor=actor, ts=ts, rid=bundle["rid"],
                capability=r["capability"],
                evidence_class=engine.evidence_class(touched),
                prereq=r["prereq"],
                evidence={"path": bundle["ingress"]["req"]["target"],
                          "touched": sorted(touched)})
        # Recorded after scoring so a finding cannot satisfy its own prerequisite.
        self.store.visit(actor, bundle["ingress"]["req"]["path"], ts)
        self.scored += 1


async def tap_server(sock_path, pipeline):
    """One-way intake for app-reported records. The app writes; it never reads."""
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    os.makedirs(os.path.dirname(sock_path), exist_ok=True)

    async def handle(reader, _writer):
        while True:
            try:
                line = await reader.readline()
            except (ConnectionResetError, asyncio.LimitOverrunError):
                break
            if not line:
                break
            try:
                pipeline.feed(json.loads(line))
            except (json.JSONDecodeError, R.BadRecord):
                continue        # malformed input from a compromised app: drop

    server = await asyncio.start_unix_server(handle, sock_path)
    os.chmod(sock_path, 0o666)
    return server


async def ticker(pipeline, interval=0.1):
    while True:
        await asyncio.sleep(interval)
        try:
            pipeline.tick()
        except Exception:
            pass
