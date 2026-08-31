"""The findings catalog — scorer-side only.

findings.yaml is loaded here and here alone. It never enters the app image, so
there is no stripped runtime copy to generate and no RUNTIME_FIELDS to maintain:
tools/strip_catalog.py and findings.runtime.yaml are obsolete under the split.
"""
import os, yaml

PATH = os.environ.get("SPRKL_CATALOG",
                      os.path.join(os.path.dirname(os.path.dirname(
                          os.path.abspath(__file__))), "findings.yaml"))
_cache = None


def all_findings():
    global _cache
    if _cache is None:
        with open(PATH) as fh:
            _cache = yaml.safe_load(fh)["findings"]
    return _cache


def by_id(fid):
    return next((f for f in all_findings() if f["id"] == fid), None)


def live_ids():
    return {f["id"] for f in all_findings() if f.get("status") == "live"}


def difficulty(fid):
    f = by_id(fid)
    return int(f.get("difficulty", 3)) if f else 3
