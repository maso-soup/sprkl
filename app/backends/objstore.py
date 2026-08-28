"""In-memory object store ("bucket"). Anonymous listing is enabled -> misconfig."""
_bucket = {}


def put(key, data, private=False):
    _bucket[key] = {"data": data, "private": private}


def get(key):
    o = _bucket.get(key)
    return o["data"] if o else None


def list_keys():
    return sorted(_bucket.keys())
