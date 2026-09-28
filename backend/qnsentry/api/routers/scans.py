import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from kombu.exceptions import OperationalError as QueueUnavailable
from sqlalchemy import select
from sqlalchemy.orm import Session

from qnsentry.api.schemas import FindingOut, ModuleRunOut, ScanOut, ScanSummary
from qnsentry.config import settings
from qnsentry.db.models import Domain, Finding, ModuleRun, Scan, ScanStatus
from qnsentry.db.session import get_db
from qnsentry.modules import MODULES
from qnsentry.worker.tasks import run_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["scans"])


def is_stuck(scan: Scan) -> bool:
    """A queued or running scan older than the scan timeout will not finish anymore."""
    timeout = timedelta(minutes=settings.scan_timeout_minutes)
    return scan.created_at < datetime.now(UTC) - timeout


def get_scan_or_404(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


@router.post(
    "/domains/{domain_id}/scans",
    response_model=ScanSummary,
    status_code=status.HTTP_201_CREATED,
)
def start_scan(domain_id: int, db: Session = Depends(get_db)) -> Scan:
    domain = db.get(Domain, domain_id)
    if domain is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Domain not found")

    # Only one active scan per domain: a second one would repeat the same work
    active = db.scalar(
        select(Scan).where(
            Scan.domain_id == domain.id,
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
        )
    )
    if active is not None:
        if not is_stuck(active):
            raise HTTPException(
                status.HTTP_409_CONFLICT, "A scan is already running for this domain."
            )
        # A stuck scan (e.g. after a worker crash) must not block the domain forever
        active.mark_failed("The scan did not finish in time.")
        db.commit()

    # One module run per module, in the order the worker runs them
    scan = Scan(
        domain=domain,
        module_runs=[ModuleRun(module=module.name) for module in MODULES],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Queue the scan in Redis; a worker picks it up (the API does not wait)
    try:
        run_scan.delay(scan.id)
    except QueueUnavailable as error:
        logger.exception("Could not queue scan %s", scan.id)
        scan.mark_failed("The scan could not be queued.")
        db.commit()
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The scan queue is unavailable. Try again later.",
        ) from error
    return scan


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanOut:
    scan = get_scan_or_404(db, scan_id)
    return ScanOut(
        id=scan.id,
        domain=scan.domain.name,
        status=scan.status,
        created_at=scan.created_at,
        modules=[ModuleRunOut.model_validate(run) for run in scan.module_runs],
    )


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def get_findings(scan_id: int, db: Session = Depends(get_db)) -> list[Finding]:
    return get_scan_or_404(db, scan_id).findings
