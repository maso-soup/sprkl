"""Every live finding must be reachable: one genuine exploit each, credited by
the scorer. Complements the negative test — benign traffic scores nothing.
"""
import time

from scorer import catalog
from tests.sweep import sweep


def _solved_when_settled(stack, expect, deadline_s=12.0):
    """Poll until every expected finding is credited or the deadline passes.

    A tap can still be in the app's async send queue when the sweep returns, so a
    single drain can miss a late event; draining repeatedly catches it. Avoids a
    fixed-sleep race in the test without weakening the scorer.
    """
    end = time.time() + deadline_s
    got = set()
    while time.time() < end:
        stack.settle(0.3)
        got = stack.solved()
        if expect <= got:
            break
    return got


def test_every_live_finding_is_solved(stack):
    sweep(stack)
    live = catalog.live_ids()
    got = _solved_when_settled(stack, live)
    missing = sorted(live - got)
    assert not missing, f"{len(missing)} live findings unsolved: {missing}"


def test_provenance_split_is_reported(stack):
    """After an RCE, later solves are tagged assisted and scored separately."""
    sweep(stack)
    _solved_when_settled(stack, catalog.live_ids())
    score = stack.score()
    assert score["solved"] == 95
    assert score["first_capability"] is not None
    assert score["blackbox"] + score["post_capability"] >= score["solved"] - 5
    assert score["proxy_observed"] > 0 and score["app_reported"] > 0
