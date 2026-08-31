"""SPRKL configuration.

Every value that a finding depends on is supplied per run by the scorer through
the seed spec, so no two runs share a secret and nothing here is a constant a
tester can memorise between runs. Values are randomised; the *property* each one
carries is preserved (the JWT secret is drawn from a wordlist, because
`jwt-weak-secret` requires it to stay crackable).

There is no scoring key and no findings catalog in this process. Both live in
the scorer container.
"""
import base64, json, os, time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("SPRKL_DATA", os.path.join(BASE_DIR, "instance"))
DB_PATH = os.path.join(DATA_DIR, "sprkl.db")
SEED_FILE = os.environ.get("SPRKL_SEED_FILE", "/run/sprkl/seed.json")

APP_PORT = int(os.environ.get("SPRKL_APP_PORT", "8081"))
COLLAB_BASE = os.environ.get("SPRKL_COLLAB_BASE", "http://scorer:8088/c")


def _load_spec(path, wait=30):
    """Block briefly for the scorer to publish the run spec.

    The scorer generates the run before the app may serve traffic, so waiting
    here is the whole startup ordering contract — no compose healthcheck needed.
    """
    end = time.time() + wait
    while time.time() < end:
        try:
            with open(path) as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            time.sleep(0.25)
    raise RuntimeError(f"no run spec at {path}; is the scorer up?")


def _standalone_spec():
    """Dev/test convenience: no scorer attached, so generate a spec in-process.

    Only ever taken when SPRKL_STANDALONE=1. The app image does not contain
    scorer/, so this branch cannot be reached in a real run.
    """
    import sys
    sys.path.insert(0, BASE_DIR)
    from scorer.seedgen import generate
    return generate()["spec"]


SPEC = (_standalone_spec() if os.environ.get("SPRKL_STANDALONE") == "1"
        else _load_spec(SEED_FILE))

_ENV = SPEC.get("env", {})
TOKEN_PREFIX = SPEC.get("token_prefix", "SPRKL-LOCAL-")

FLASK_SECRET = _ENV["SPRKL_FLASK_SECRET"]
JWT_SECRET = _ENV["SPRKL_JWT_SECRET"]
COOKIE_MAC_SECRET = base64.b64decode(_ENV["SPRKL_COOKIE_MAC_SECRET"])
COUPON_AES_KEY = base64.b64decode(_ENV["SPRKL_COUPON_AES_KEY"])
WEAK_RNG_SEED = int(_ENV["SPRKL_WEAK_RNG_SEED"])
IAM_SECRET = _ENV["SPRKL_IAM_SECRET"]
