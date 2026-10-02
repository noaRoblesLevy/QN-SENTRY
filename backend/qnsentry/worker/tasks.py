import logging
from dataclasses import asdict
from datetime import UTC, datetime

from sqlalchemy import update
from sqlalchemy.orm import Session

from qnsentry.db import models
from qnsentry.db.models import ModuleStatus, ScanStatus
from qnsentry.db.session import SessionLocal
from qnsentry.modules import MODULES_BY_NAME
from qnsentry.modules.base import ScanContext
from qnsentry.worker.celery_app import celery_app

logger = logging.getLogger(__name__)

# Warnings stored per module run; more are summarised in one last warning
MAX_WARNINGS = 20


def now() -> datetime:
    return datetime.now(UTC)


@celery_app.task
def run_scan(scan_id: int) -> None:
    """Run all modules of a scan and store their findings (contract 10.3)."""
    with SessionLocal() as db:
        if not claim_scan(db, scan_id):
            handle_unclaimed_scan(db, scan_id)
            return

        scan = db.get(models.Scan, scan_id)
        try:
            run_modules(db, scan)
        except Exception:
            # Something outside the modules went wrong: the scan could not run
            logger.exception("Scan %s failed", scan_id)
            db.rollback()
            scan.mark_failed("The scan stopped because of an unexpected error.")
            db.commit()


def claim_scan(db: Session, scan_id: int) -> bool:
    """Move the scan from queued to running, in one statement.

    Only one worker can succeed: if the same task is delivered twice, the second
    delivery finds the scan no longer queued and does not run it again.
    """
    result = db.execute(
        update(models.Scan)
        .where(models.Scan.id == scan_id, models.Scan.status == ScanStatus.QUEUED)
        .values(status=ScanStatus.RUNNING, started_at=now())
    )
    db.commit()
    return result.rowcount == 1


def handle_unclaimed_scan(db: Session, scan_id: int) -> None:
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        logger.warning("Scan %s does not exist", scan_id)
    elif scan.status == ScanStatus.RUNNING:
        # The task was delivered again because the worker running it stopped
        logger.warning("Scan %s was interrupted, marking it failed", scan_id)
        scan.mark_failed("The worker stopped during this scan. Start a new scan.")
        db.commit()
    else:
        logger.info("Scan %s is already %s, not running it again", scan_id, scan.status)


def run_modules(db: Session, scan: models.Scan) -> None:
    context = ScanContext(domain=scan.domain.name)
    any_failed = False

    for module_run in scan.module_runs:
        module = MODULES_BY_NAME[module_run.module]
        module_run.status = ModuleStatus.RUNNING
        module_run.started_at = now()
        db.commit()

        context.warnings = []
        try:
            findings = module.run(context)
        except Exception as error:
            # One failing module does not stop the others (contract 10.3.1)
            logger.exception("Module %s failed for scan %s", module.name, scan.id)
            module_run.status = ModuleStatus.FAILED
            module_run.error = str(error) or type(error).__name__
            any_failed = True
        else:
            for finding in findings:
                db.add(models.Finding(scan=scan, **asdict(finding)))
            module_run.finding_count = len(findings)
            module_run.status = ModuleStatus.COMPLETED

        # Also kept when the module failed afterwards: they show what went wrong before
        module_run.warnings = limit_warnings(context.warnings)
        module_run.finished_at = now()
        db.commit()

    # The warnings belong to the module runs, not to the information shared between modules
    scan.context = {key: value for key, value in asdict(context).items() if key != "warnings"}
    scan.status = ScanStatus.PARTIAL if any_failed else ScanStatus.COMPLETED
    scan.finished_at = now()
    db.commit()


def limit_warnings(warnings: list[str]) -> list[str]:
    """The warnings without duplicates, in order, at most MAX_WARNINGS.

    A module that warns once per item (e.g. per document) would otherwise flood the
    database, the dashboard and the report.
    """
    unique = list(dict.fromkeys(w.strip() for w in warnings if w and w.strip()))
    if len(unique) <= MAX_WARNINGS:
        return unique
    hidden = len(unique) - (MAX_WARNINGS - 1)
    return unique[: MAX_WARNINGS - 1] + [f"... and {hidden} more warnings"]
