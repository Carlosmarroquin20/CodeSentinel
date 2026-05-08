# Sample vulnerable configuration — used only for testing and demonstration.
# This file intentionally contains patterns that CodeSentinel is designed to detect.

import hashlib

DATABASE_HOST = "localhost"
DATABASE_PORT = 5432
DATABASE_NAME = "production_db"

# CS005: hardcoded credential
DATABASE_PASSWORD = "MyH@rdcod3dP4ssw0rd!"

# CS005: hardcoded API key
API_KEY = "supersecretapikey123456789"


def hash_password_insecure(password: str) -> str:
    # CS101: weak hash algorithm
    return hashlib.md5(password.encode()).hexdigest()


def hash_with_sha1(password: str) -> str:
    # CS101: weak hash algorithm
    return hashlib.sha1(password.encode()).hexdigest()
