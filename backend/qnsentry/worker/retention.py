"""Delete scan results after the retention period (issue #46, GDPR storage limitation).

Findings contain personal data (names, business email addresses, breach records). The
legal framework (docs/project/05-legal-ethical.md, 5.3) promises that scan results are
deleted after RETENTION_DAYS (default 90). Celery Beat runs this task once a day.

Deleting a scan also deletes its module runs and findings: the foreign keys use
ON DELETE CASCADE, so the database removes them in the same statement.

A scan that is still queued or running is kept, unless it is older than the scan
timeout: then it is stuck (e.g. its worker stopped) and will never finish, and keeping
it would keep its personal data forever.

Beat runs the clean-up at 03:00 UTC; the worker also runs it once when it starts, so a
machine that is rarely on at night (a demo laptop) still deletes expired results.
"""

import logging
from datetime import UTC, datetime, timedelta

from celery.signals import worker_ready
from sqlalchemy import Delete, delete, or_

from qnsentry.config import settings
from qnsentry.db import models
from qnsentry.db.models import ScanStatus
from qnsentry.db.session import SessionLocal
from qnsentry.worker.celery_app import celery_app

logger = logging.getLogger(__name__)

UNFINISHED = (ScanStatus.QUEUED, ScanStatus.RUNNING)


def expired_scans(now: datetime, retention_days: int, scan_timeout_minutes: int) -> Delete:
    """The statement that deletes the scans created before the retention period.

    Finished scans go; queued or running ones only when they are older than the scan
    timeout, because then they are stuck and will never finish.
    """
    cutoff = now - timedelta(days=retention_days)
    stuck_before = now - timedelta(minutes=scan_timeout_minutes)
    return delete(models.Scan).where(
        models.Scan.created_at < cutoff,
        or_(models.Scan.status.not_in(UNFINISHED), models.Scan.created_at < stuck_before),
    )


@celery_app.task
def delete_expired_scans() -> int:
    """Delete expired scans; returns how many. Logs only the number, never personal data."""
    with SessionLocal() as db:
        result = db.execute(
            expired_scans(datetime.now(UTC), settings.retention_days, settings.scan_timeout_minutes)
        )
        db.commit()
    deleted = result.rowcount or 0
    logger.info(
        "Retention: deleted %s scan(s) older than %s days, with their findings",
        deleted,
        settings.retention_days,
    )
    return deleted


@worker_ready.connect
def clean_up_on_start(**_) -> None:
    """Queue the clean-up once when a worker starts. Running it twice is harmless."""
    delete_expired_scans.delay()
