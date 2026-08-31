"""Fake cloud metadata service (169.254.169.254)."""
from .. import config

CREDS = {
    "AccessKeyId": "AKIA-SPRKL-" + config.TOKEN_PREFIX.strip("-").split("-")[-1],
    "SecretAccessKey": config.IAM_SECRET,
    "Token": "sprkl-session-token",
}


def get(path):
    if "iam" in path or "credentials" in path or path.rstrip("/").endswith("security-credentials"):
        import json
        return json.dumps(CREDS)
    return "ami-id\ninstance-id\niam/"
