"""Fake cloud metadata service (169.254.169.254). Returns canary IAM creds."""
CREDS = {
    "AccessKeyId": "AKIA-SPRKL-CANARY",
    "SecretAccessKey": "SPRKL-CANARY-IAM-SECRET",
    "Token": "sprkl-canary-session-token",
}


def get(path):
    if "iam" in path or "credentials" in path or path.rstrip("/").endswith("security-credentials"):
        import json
        return json.dumps(CREDS)
    return "ami-id\ninstance-id\niam/"
