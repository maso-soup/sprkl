"""Spin up a real SPRKL instance (both ports) once per test session.

Tests drive genuine exploits over HTTP and assert the oracle recorded them —
exactly how an external scorer would observe ground truth.
"""
import os, sys, time, socket, subprocess, tempfile
import pytest, requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PORT, ORACLE_PORT = 8091, 9091
ORACLE_KEY = "test-key"
BASE = f"http://127.0.0.1:{APP_PORT}"
ORACLE = f"http://127.0.0.1:{ORACLE_PORT}"


def _wait(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@pytest.fixture(scope="function")
def server():
    env = dict(os.environ)
    env.update(SPRKL_APP_PORT=str(APP_PORT), SPRKL_ORACLE_PORT=str(ORACLE_PORT),
               SPRKL_ORACLE_KEY=ORACLE_KEY,
               SPRKL_DATA=tempfile.mkdtemp(prefix="sprkl-test-"),
               SPRKL_COLLAB_BASE=f"{BASE}/collab")
    py = os.path.join(ROOT, ".venv", "bin", "python")
    proc = subprocess.Popen([py, "run.py"], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert _wait(APP_PORT) and _wait(ORACLE_PORT), "server did not start"
    yield {"base": BASE, "oracle": ORACLE, "key": ORACLE_KEY}
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()


def solved(server):
    r = requests.get(f"{server['oracle']}/oracle/solves",
                     headers={"X-Oracle-Key": server["key"]}, timeout=5)
    return {s["finding_id"] for s in r.json()["solves"]}
