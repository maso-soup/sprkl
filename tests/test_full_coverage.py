"""Every live finding must be reachable: one genuine exploit each, credited by
the scorer. Complements the negative test — benign traffic scores nothing.
"""
from scorer import catalog
from tests.sweep import sweep


def test_every_live_finding_is_solved(stack):
    sweep(stack)
    stack.settle(2.0)
    got = stack.solved()
    missing = sorted(catalog.live_ids() - got)
    assert not missing, f"{len(missing)} live findings unsolved: {missing}"


def test_provenance_split_is_reported(stack):
    """After an RCE, later solves are tagged assisted and scored separately."""
    sweep(stack)
    stack.settle(2.0)
    score = stack.score()
    assert score["solved"] == 95
    assert score["first_capability"] is not None
    assert score["blackbox"] + score["post_capability"] >= score["solved"] - 5
    assert score["proxy_observed"] > 0 and score["app_reported"] > 0
