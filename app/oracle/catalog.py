"""Load the findings catalog (single source of truth) into memory."""
import yaml
from .. import config

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
