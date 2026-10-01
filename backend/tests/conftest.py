"""Shared test setup.

Settings are read when the API, the worker or the models are imported. Most tests need
no database, so they get harmless values here. The API tests in tests/api/ run against a
real PostgreSQL only when QNSENTRY_TEST_DATABASE=1 and the POSTGRES_* variables point to a
database that may be emptied (see tests/api/conftest.py).
"""

import os

TEST_SETTINGS = {
    "POSTGRES_USER": "test",
    "POSTGRES_PASSWORD": "test",
    "POSTGRES_DB": "test",
    "DOMAIN_VERIFICATION_SECRET": "test-secret-for-domain-verification-0123456789",
}
for name, value in TEST_SETTINGS.items():
    os.environ.setdefault(name, value)
