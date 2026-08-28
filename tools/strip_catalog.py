#!/usr/bin/env python3
"""Generate findings.runtime.yaml from findings.yaml (single source of truth).

findings.yaml carries the answer key: `location`, `gui`, `hint` and `description`
say where each vulnerability lives and how to reach it. The running app never
reads those four — only `tools/gen_cheatsheet.py` does. But `COPY . .` puts the
catalog inside the image at /app, where SPRKL's own live findings (path-traversal-
invoice, file-inclusion-rce, os-command-injection, python-pickle-rce, ...) can read
it. One solve would hand an agent a map to the other 94.

So the image ships this stripped copy instead: every record, but only the fields
`app/oracle/` actually serves. Relocating the full catalog would not help — the
RCE findings can read any path, and app/config.py names it.

Usage: python tools/strip_catalog.py [--check]
  --check : exit non-zero if findings.runtime.yaml is stale (for CI).
"""
import sys, os, yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "findings.yaml")
OUT = os.path.join(ROOT, "findings.runtime.yaml")

sys.path.insert(0, ROOT)
# Imported, not re-declared: if the oracle API starts serving another field, the
# stripped catalog picks it up automatically instead of silently missing it.
from app.oracle.catalog import RUNTIME_FIELDS  # noqa: E402

HEADER = """\
# ==========================================================================
# SPRKL — RUNTIME findings catalog  (GENERATED — do not edit by hand)
# ==========================================================================
# Generated from findings.yaml by `python tools/strip_catalog.py`.
#
# This is the copy that ships inside the container image. It keeps every
# record but drops the answer-key fields (location, gui, hint, description)
# so that a file-read or RCE finding cannot leak a walkthrough for the rest.
# Edit findings.yaml and regenerate; never edit this file.
# ==========================================================================
"""


def load():
    with open(CATALOG) as fh:
        return yaml.safe_load(fh)["findings"]


def strip(findings):
    """Keep every record, but only the fields the running app serves. Fields are
    emitted in RUNTIME_FIELDS order so the output is stable across runs."""
    out = []
    for f in findings:
        out.append({k: f[k] for k in RUNTIME_FIELDS if k in f})
    return out


def render(findings):
    body = yaml.safe_dump({"findings": strip(findings)},
                          sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=100)
    return HEADER + "\n" + body


def main():
    text = render(load())
    if "--check" in sys.argv:
        current = open(OUT).read() if os.path.exists(OUT) else ""
        if current != text:
            print("findings.runtime.yaml is stale — run: "
                  "python tools/strip_catalog.py", file=sys.stderr)
            return 1
        print("findings.runtime.yaml is up to date.")
        return 0
    with open(OUT, "w") as fh:
        fh.write(text)
    n = len(load())
    dropped = sorted({k for f in load() for k in f} - set(RUNTIME_FIELDS))
    print(f"wrote {OUT} ({n} records, dropped: {', '.join(dropped)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
