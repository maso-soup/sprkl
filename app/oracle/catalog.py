"""Load the findings catalog (single source of truth) into memory.

Two catalogs exist. `findings.yaml` is the source of truth and carries the answer
key (location / gui / hint / description). `findings.runtime.yaml`, generated from
it by `tools/strip_catalog.py`, keeps only RUNTIME_FIELDS and is what ships inside
the container image — so a file-read or RCE finding cannot leak a walkthrough for
the rest. See config.CATALOG_PATH for which one gets loaded.
"""
import yaml
from .. import config

# The only fields the running app is allowed to know about. The oracle API serves
# exactly these; nothing else in app/ reads any other field. tools/strip_catalog.py
# imports this list, so adding a field here is enough to carry it into the image.
RUNTIME_FIELDS = ("id", "title", "family", "category", "skill",
                  "owasp_web", "owasp_api", "cwe", "difficulty",
                  "tier", "status")

_cache = None


def all_findings():
    global _cache
    if _cache is None:
        with open(config.CATALOG_PATH) as fh:
            _cache = yaml.safe_load(fh)["findings"]
    return _cache


def by_id(fid):
    for f in all_findings():
        if f["id"] == fid:
            return f
    return None


def live_ids():
    return {f["id"] for f in all_findings() if f["status"] == "live"}
