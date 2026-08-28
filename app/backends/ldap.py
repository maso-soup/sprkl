"""Fake LDAP directory. search() takes a raw filter string that is built by the
caller via concatenation, so `*` and `)` change the query — LDAP injection."""
import re

_entries = []


def seed(entries):
    global _entries
    _entries = list(entries)


def search(filter_str):
    """Support a minimal subset: (&(uid=X)(...)) and (uid=X). `*` is a wildcard."""
    results = []
    # extract (attr=value) leaves
    leaves = re.findall(r"\(([a-zA-Z]+)=([^()]*)\)", filter_str)
    conj = filter_str.strip().startswith("(&")
    for e in _entries:
        checks = []
        for attr, val in leaves:
            actual = str(e.get(attr, ""))
            if val == "*" or val == "":
                checks.append(True)
            elif "*" in val:
                pat = "^" + re.escape(val).replace(r"\*", ".*") + "$"
                checks.append(bool(re.match(pat, actual)))
            else:
                checks.append(actual == val)
        if not leaves:
            continue
        ok = all(checks) if conj else any(checks)
        if ok:
            results.append(e)
    return results
