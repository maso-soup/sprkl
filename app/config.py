"""SPRKL configuration. Values are intentionally weak where a finding depends on it."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("SPRKL_DATA", os.path.join(BASE_DIR, "instance"))
DB_PATH = os.path.join(DATA_DIR, "sprkl.db")
CATALOG_PATH = os.path.join(BASE_DIR, "findings.yaml")

# Ports
APP_PORT = int(os.environ.get("SPRKL_APP_PORT", "8080"))       # attackable storefront
ORACLE_PORT = int(os.environ.get("SPRKL_ORACLE_PORT", "9090")) # scoring / source of truth

# Oracle scoring API key (poller must send this in X-Oracle-Key)
ORACLE_KEY = os.environ.get("SPRKL_ORACLE_KEY", "sprkl-oracle-dev-key")

# --- Intentionally weak secrets (findings depend on these) ---
FLASK_SECRET = "sprkl"                      # jwt-weak-secret / guessable
JWT_SECRET = "sprkl"                        # HS256 crackable dictionary word
COOKIE_MAC_SECRET = b"s3cr3t"               # md5(secret||data) length-extension
COUPON_AES_KEY = b"SPRKLsparkling16"        # 16 bytes, CBC padding oracle
WEAK_RNG_SEED = 1337                        # crypto-weak-randomness

# The collab (OAST) base the app advertises to itself for internal callbacks.
COLLAB_BASE = os.environ.get("SPRKL_COLLAB_BASE", f"http://127.0.0.1:{APP_PORT}/collab")
