from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from qnsentry.api.schemas import FindingOut, ModuleRunOut, ScanOut, ScanSummary
from qnsentry.db.models import Domain, Finding, ModuleRun, Scan, ScanStatus
from qnsentry.db.session import get_db
from qnsentry.modules import MODULES
from qnsentry.worker.tasks import run_scan

router = APIRouter(prefix="/api", tags=["scans"])


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
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A scan is already running for this domain."
        )

    # One module run per module, in the order the worker runs them
    scan = Scan(
        domain=domain,
        module_runs=[ModuleRun(module=module.name) for module in MODULES],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Queue the scan in Redis; a worker picks it up (the API does not wait)
    run_scan.delay(scan.id)
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
