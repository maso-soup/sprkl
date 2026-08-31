"""Replay a transcript through a ruleset. The proof that scoring is a pure
function of (transcript, ruleset): re-run an old run, or a new ruleset over it.
"""
import argparse, json, os, tempfile
from shared import records as R
from . import ingest, store as store_mod
from . import rules as _rules  # noqa: F401


def replay(path, store_path=None):
    manifest = None
    with open(path) as fh:
        first = json.loads(fh.readline())
    manifest = first if first.get("t") == "manifest" else None
    store = store_mod.Store(store_path or os.path.join(
        tempfile.mkdtemp(prefix="replay-"), "solves.db"))

    class _Null:
        path = "(replay)"
        count = 0
        def write(self, rec): self.count += 1
    pipe = ingest.Pipeline(_Null(), store, manifest)
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                pipe.feed(json.loads(line), record_to_transcript=False)
            except (json.JSONDecodeError, R.BadRecord):
                continue
    pipe.drain()
    return store


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript")
    ap.add_argument("--store")
    args = ap.parse_args()
    st = replay(args.transcript, args.store)
    print(json.dumps(st.score(), indent=2))
