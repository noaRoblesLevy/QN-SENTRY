"""Permission (#3) and ownership verification (#48) of a domain."""

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from qnsentry import verification
from qnsentry.api.schemas import DomainOut
from qnsentry.db.models import Domain
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
