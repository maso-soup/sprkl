"""Load the findings catalog (single source of truth) into memory.

Two catalogs exist. `findings.yaml` is the source of truth and carries the answer
key (location / gui / hint / description). `findings.runtime.yaml`, generated from
it by `tools/strip_catalog.py`, keeps only RUNTIME_FIELDS and is what ships inside
the container image — so a file-read or RCE finding cannot leak a walkthrough for
the rest. See config.CATALOG_PATH for which one gets loaded.
"""
import yaml
from .. import config
from .fields import RUNTIME_FIELDS  # noqa: F401 - re-exported as catalog.RUNTIME_FIELDS

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
