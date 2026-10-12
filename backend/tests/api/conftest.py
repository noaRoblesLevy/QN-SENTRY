"""API tests against a real PostgreSQL.

They only run with QNSENTRY_TEST_DATABASE=1, and then they EMPTY the database the
POSTGRES_* variables point to, so never use the database of a real installation:

    docker run -d --name qnsentry-testdb -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:17-alpine
    QNSENTRY_TEST_DATABASE=1 POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=55432 \
        POSTGRES_USER=postgres POSTGRES_PASSWORD=test POSTGRES_DB=postgres pytest tests/api

Use 127.0.0.1, not localhost: on Windows "localhost" first tries IPv6 and each connection
waits for that to fail (2 minutes instead of a second for these tests).

The schema is made with the real migrations, so these tests also prove that the
migrations and the models match what the API expects.
"""

import os

import pytest

if os.environ.get("QNSENTRY_TEST_DATABASE") != "1":
    pytest.skip("API tests need a test database: set QNSENTRY_TEST_DATABASE=1", allow_module_level=True)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from qnsentry.api.main import app  # noqa: E402
from qnsentry.db.migrate import migrate  # noqa: E402
from qnsentry.db.session import engine  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def schema():
    migrate()


@pytest.fixture(autouse=True)
def empty_database():
    with engine.begin() as connection:
        connection.execute(text("TRUNCATE clients RESTART IDENTITY CASCADE"))


@pytest.fixture
def api():
    return TestClient(app)


@pytest.fixture
def queued(monkeypatch):
    """Scans that would be put in Redis; no Redis is needed."""
    tasks = []
    monkeypatch.setattr("qnsentry.api.routers.scans.run_scan.delay", lambda scan_id: tasks.append(scan_id))
    return tasks
