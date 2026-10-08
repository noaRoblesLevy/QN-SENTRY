"""Permission (#3), ownership verification (#48) and port scan approvals (#81) of a domain."""

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from qnsentry import verification
from qnsentry.api.schemas import AddressOut, DomainOut, PortScanApprovalsIn
from qnsentry.db.models import Domain, PortScanApproval
from qnsentry.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["domains"])


def get_domain_or_404(db: Session, domain_id: int) -> Domain:
    domain = db.get(Domain, domain_id)
    if domain is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Domain not found")
    return domain


def record_present(domain: Domain) -> bool:
    """True when the domain's TXT record is in its DNS now.

    A failed lookup is not "absent": it raises a 503, so a DNS problem never looks like a
    withdrawn permission and never lets a scan through either.
    """
    try:
        records = verification.txt_records(domain.name)
    except verification.VerificationLookupFailed as error:
        logger.warning("Verification lookup failed: %s", error)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"The DNS records of {domain.name} could not be looked up. Try again in a moment.",
        ) from error
    return verification.has_verification_record(records, domain.verification_record)


@router.post("/domains/{domain_id}/permission", response_model=DomainOut)
def confirm_permission(domain_id: int, db: Session = Depends(get_db)) -> Domain:
    """Record that the user confirmed they may scan the domain.

    New domains are confirmed when they are added; this is for domains added before the
    confirmation existed (migration 0003).
    """
    domain = get_domain_or_404(db, domain_id)
    if domain.permission_confirmed_at is None:
        domain.permission_confirmed_at = datetime.now(UTC)
        db.commit()
        db.refresh(domain)
    return domain


@router.post("/domains/{domain_id}/verify", response_model=DomainOut)
def verify_domain(domain_id: int, db: Session = Depends(get_db)) -> Domain:
    """Look up the TXT records of the domain and mark it verified when the record is there."""
    domain = get_domain_or_404(db, domain_id)
    if domain.verified_at is not None:
        return domain

    if not record_present(domain):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"The TXT record {domain.verification_record} was not found on {domain.name}. Add it to "
            "the domain's DNS and try again; a new record can take a few minutes to become visible.",
        )

    domain.verified_at = datetime.now(UTC)
    db.commit()
    db.refresh(domain)
    return domain


# ---------- Port scan approvals (#81) ----------


def discovered_addresses(domain: Domain) -> dict[str, list[str]]:
    """{ip: [host names]} from the newest scan that found live hosts (Attack Surface, #4)."""
    for scan in domain.scans:
        live_hosts = (scan.context or {}).get("live_hosts") or []
        if live_hosts:
            addresses: dict[str, list[str]] = {}
            for host in live_hosts:
                for ip in host.get("ips", []):
                    addresses.setdefault(ip, []).append(host["name"])
            return addresses
    return {}


def addresses_of(domain: Domain) -> list[AddressOut]:
    discovered = discovered_addresses(domain)
    approved = set(domain.port_scan_ips)
    ips = list(discovered) + sorted(approved - set(discovered))
    return [AddressOut(ip=ip, hosts=discovered.get(ip, []), approved=ip in approved) for ip in ips]


@router.get("/domains/{domain_id}/addresses", response_model=list[AddressOut])
def list_addresses(domain_id: int, db: Session = Depends(get_db)) -> list[AddressOut]:
    """The addresses the latest scan found for the domain, and which may get a port scan."""
    return addresses_of(get_domain_or_404(db, domain_id))


@router.put("/domains/{domain_id}/port-scan", response_model=list[AddressOut])
def set_port_scan_approvals(
    domain_id: int, payload: PortScanApprovalsIn, db: Session = Depends(get_db)
) -> list[AddressOut]:
    """Replace the addresses that may get a port scan.

    Only for a verified domain, and only addresses its hosts resolved to in the latest scan:
    an address the scan did not find for this domain cannot be approved through it.
    """
    domain = get_domain_or_404(db, domain_id)
    if not domain.verified:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Verify that you control {domain.name} before approving addresses for a port scan.",
        )
    discovered = discovered_addresses(domain)
    unknown = [ip for ip in payload.ips if ip not in discovered]
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"{unknown[0]} was not found for {domain.name} in the latest scan.",
        )

    wanted = set(payload.ips)
    for approval in list(domain.port_scan_approvals):
        if approval.ip not in wanted:
            domain.port_scan_approvals.remove(approval)
    already = set(domain.port_scan_ips)
    for ip in payload.ips:
        if ip not in already:
            domain.port_scan_approvals.append(PortScanApproval(ip=ip))
    db.commit()
    db.refresh(domain)
    return addresses_of(domain)
