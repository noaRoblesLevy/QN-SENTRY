"""Delete scan results after the retention period (issue #46, GDPR storage limitation).

Findings contain personal data (names, business email addresses, breach records). The
legal framework (docs/project/05-legal-ethical.md, 5.3) promises that scan results are
deleted after RETENTION_DAYS (default 90). Celery Beat runs this task once a day.

Deleting a scan also deletes its module runs and findings: the foreign keys use
ON DELETE CASCADE, so the database removes them in the same statement.
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import Delete, delete

from qnsentry.config import settings
from qnsentry.db import models
from qnsentry.db.models import ScanStatus
from qnsentry.db.session import SessionLocal
from qnsentry.worker.celery_app import celery_app

logger = logging.getLogger(__name__)

# A scan that is still being worked on is never deleted, whatever its age
UNFINISHED = (ScanStatus.QUEUED, ScanStatus.RUNNING)


def expired_scans(now: datetime, retention_days: int) -> Delete:
    """The statement that deletes finished scans created before the retention period."""
    cutoff = now - timedelta(days=retention_days)
    return delete(models.Scan).where(
        models.Scan.created_at < cutoff,
        models.Scan.status.not_in(UNFINISHED),
    )


@celery_app.task
def delete_expired_scans() -> int:
    """Delete expired scans; returns how many. Logs only the number, never personal data."""
    with SessionLocal() as db:
        result = db.execute(expired_scans(datetime.now(UTC), settings.retention_days))
        db.commit()
    deleted = result.rowcount or 0
    logger.info(
        "Retention: deleted %s scan(s) older than %s days, with their findings",
        deleted,
        settings.retention_days,
    )
    return deleted
