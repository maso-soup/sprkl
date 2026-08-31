"""Tiny Mongo-style store with operator interpretation — the NoSQL-injection sink.

Documents are plain dicts. A filter value may be a bare value (equality) or an
operator object like {"$ne": null}, {"$gt": ""}, {"$regex": "..."}, or
{"$where": "<expr>"} — all honored, which is exactly the vulnerability.
"""
import re

_collections = {}


def seed(name, docs):
    _collections[name] = [dict(d) for d in docs]


def _match_op(field_val, cond):
    if isinstance(cond, dict):
        for op, arg in cond.items():
            if op == "$ne":
                if field_val == arg:
                    return False
            elif op == "$gt":
                if not (field_val is not None and field_val > arg):
                    return False
            elif op == "$gte":
                if not (field_val is not None and field_val >= arg):
                    return False
            elif op == "$lt":
                if not (field_val is not None and field_val < arg):
                    return False
            elif op == "$regex":
                if field_val is None or not re.search(str(arg), str(field_val)):
                    return False
            elif op == "$in":
                if field_val not in arg:
                    return False
            elif op == "$exists":
                if (field_val is not None) != bool(arg):
                    return False
            else:
                return False
        return True
    return field_val == cond


def find(name, flt):
    out = []
    for doc in _collections.get(name, []):
        ok = True
        for k, cond in (flt or {}).items():
            if k == "$where":
                try:
                    if not eval(cond, {"__builtins__": {}}, dict(doc)):  # noqa: S307
                        ok = False
                        break
                    continue
                except Exception:
                    ok = False
                    break
            if not _match_op(doc.get(k), cond):
                ok = False
                break
        if ok:
            out.append(doc)
    return out
