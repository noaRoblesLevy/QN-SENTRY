"""Tests for the GDPR retention clean-up (#46). No database: the SQL statement is checked."""

import os
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

# The worker modules read Settings when they are imported; tests need no real database
for name, value in {"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "test"}.items():
    os.environ.setdefault(name, value)

from qnsentry.config import Settings  # noqa: E402
from qnsentry.worker import retention  # noqa: E402
from qnsentry.worker.celery_app import celery_app  # noqa: E402

NOW = datetime(2026, 12, 29, 3, 0, tzinfo=UTC)


def sql(statement) -> tuple[str, dict]:
    compiled = statement.compile(dialect=postgresql.dialect())
    return str(compiled), compiled.params


def test_deletes_finished_scans_older_than_the_retention_period():
    text, params = sql(retention.expired_scans(NOW, 90, 120))

    assert text.startswith("DELETE FROM scans WHERE scans.created_at <")
    assert params["created_at_1"] == datetime(2026, 9, 30, 3, 0, tzinfo=UTC)  # 90 days earlier


def test_keeps_a_queued_or_running_scan_unless_it_is_stuck():
    # Finished, or older than the scan timeout: a running scan that old will never finish
    text, params = sql(retention.expired_scans(NOW, 90, 120))

    assert "(scans.status NOT IN" in text and " OR scans.created_at <" in text
    assert set(params["status_1"]) == {"queued", "running"}
    assert params["created_at_2"] == datetime(2026, 12, 29, 1, 0, tzinfo=UTC)  # 120 minutes earlier


@pytest.mark.parametrize("days", [0, -1])
def test_a_retention_period_below_one_day_is_refused(days):
    # A typo in .env must not delete every result each night
    with pytest.raises(ValidationError, match="retention_days"):
        Settings(postgres_user="u", postgres_password="p", postgres_db="d", domain_verification_secret="s" * 40, retention_days=days)


def test_clean_up_also_runs_when_a_worker_starts(monkeypatch):
    queued = []
    monkeypatch.setattr(retention.delete_expired_scans, "delay", lambda: queued.append(True))

    retention.worker_ready.send(sender=None)

    assert queued == [True]


def test_task_deletes_commits_and_reports_the_number(monkeypatch):
    executed = []

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, statement):
            executed.append(statement)

            class Result:
                rowcount = 3

            return Result()

        def commit(self):
            executed.append("commit")

    monkeypatch.setattr(retention, "SessionLocal", FakeSession)
    monkeypatch.setattr(retention.settings, "retention_days", 30)

    assert retention.delete_expired_scans() == 3
    assert executed[-1] == "commit"
    assert str(executed[0].compile(dialect=postgresql.dialect())).startswith("DELETE FROM scans")


def test_clean_up_is_scheduled_daily():
    schedule = celery_app.conf.beat_schedule["delete-expired-scans"]

    assert schedule["task"] == retention.delete_expired_scans.name
    assert schedule["schedule"].hour == {3}
