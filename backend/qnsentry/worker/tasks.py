import logging
from dataclasses import asdict
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from qnsentry.db import models
from qnsentry.db.models import ModuleStatus, ScanStatus
from qnsentry.db.session import SessionLocal
from qnsentry.modules import MODULES_BY_NAME
from qnsentry.modules.base import ScanContext
from qnsentry.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


def now() -> datetime:
    return datetime.now(UTC)


@celery_app.task
def run_scan(scan_id: int) -> None:
    """Run all modules of a scan and store their findings (contract 10.3)."""
    with SessionLocal() as db:
        scan = db.get(models.Scan, scan_id)
        if scan is None:
            logger.warning("Scan %s does not exist", scan_id)
            return

        try:
            run_modules(db, scan)
        except Exception:
            # Something outside the modules went wrong: the scan could not run
            logger.exception("Scan %s failed", scan_id)
            db.rollback()
            scan.status = ScanStatus.FAILED
            scan.finished_at = now()
            db.commit()


def run_modules(db: Session, scan: models.Scan) -> None:
    scan.status = ScanStatus.RUNNING
    scan.started_at = now()
    db.commit()

    context = ScanContext(domain=scan.domain.name)
    any_failed = False

    for module_run in scan.module_runs:
        module = MODULES_BY_NAME[module_run.module]
        module_run.status = ModuleStatus.RUNNING
        module_run.started_at = now()
        db.commit()

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

        module_run.finished_at = now()
        db.commit()

    scan.context = asdict(context)
    scan.status = ScanStatus.PARTIAL if any_failed else ScanStatus.COMPLETED
    scan.finished_at = now()
    db.commit()
