"""Read runtime secrets from the environment, with no committed fallback."""

import os


def load_jwt_secret() -> str:
    secret = os.environ.get("LAB_JWT_SECRET", "")
    if len(secret.encode()) < 32:
        raise RuntimeError("Set LAB_JWT_SECRET to a random secret of at least 32 bytes")
    return secret
