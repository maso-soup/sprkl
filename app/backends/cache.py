"""Naive shared cache. The cache key ignores some request headers, enabling
cache poisoning; path-based caching of *.css enables cache deception."""
_store = {}


def get(key):
    return _store.get(key)


def put(key, value):
    _store[key] = value


def clear():
    _store.clear()
