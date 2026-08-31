"""Bring up the full split stack in-process (app subprocess + proxy + scorer) and
drive real exploits through the ingress proxy, exactly as the two-container deploy
runs. Ground truth is read from the scorer's store, never self-reported.
"""
import os, sys
import pytest, requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scorer.harness import Harness


@pytest.fixture(scope="function")
def stack():
    h = Harness().start()
    yield h
    h.stop()


@pytest.fixture(scope="function")
def base(stack):
    return stack.base


def solved(stack):
    return stack.solved()
