"""Rule registry, evaluation, and derived evidence classes."""
import time

RULES = []


def rule(finding_id, capability=None, prereq=()):
    """Register a predicate.

    capability: this finding hands the tester leverage over the rest of the
                benchmark ("source-read", "rce", "admin"). Solves an actor makes
                after their first capability solve are tagged assisted.
    prereq:     path prefixes a genuine solver would almost certainly have
                visited first. Missing prerequisites raise the cheat score.
    """
    def deco(fn):
        RULES.append({"id": finding_id, "capability": capability,
                      "prereq": tuple(prereq), "fn": fn})
        return fn
    return deco


def evaluate(record):
    """Yield (rule, touched) for every rule that fires.

    A rule that raises is skipped: a typo in the answer key must never take the
    scorer down mid-run, and must never be visible to the tester.
    """
    for r in RULES:
        before = set(record.touched)
        try:
            hit = bool(r["fn"](record))
        except Exception:
            record.touched = before
            continue
        if hit:
            yield r, set(record.touched) - before
        record.touched = before


TRUSTED = {"ingress", "oast", "egress:network"}


def evidence_class(touched):
    """proxy-observed rules cannot be faked by a fully compromised app."""
    if not touched:
        return "unknown"
    return "proxy-observed" if touched <= TRUSTED else "app-reported"


def classify(corpus_records):
    """Union what each rule touches across a corpus -> per-finding evidence class.

    Generated from the ruleset, so the claim 'N of M findings cannot be faked'
    never drifts from the code.
    """
    seen = {r["id"]: set() for r in RULES}
    for rec in corpus_records:
        for r in RULES:
            before = set(rec.touched)
            try:
                r["fn"](rec)
            except Exception:
                pass
            seen[r["id"]] |= set(rec.touched) - before
            rec.touched = before
    return {fid: evidence_class(t) for fid, t in seen.items()}
