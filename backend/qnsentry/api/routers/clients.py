import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from qnsentry.api.routers.domains import refuse_while_scanning
from qnsentry.api.schemas import (
    ClientCreate,
    ClientDetail,
    ClientOut,
    ClientUpdate,
    DomainCreate,
    DomainOut,
)
from qnsentry.db.models import Client, Domain
from qnsentry.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["clients"])


def get_client_or_404(db: Session, client_id: int) -> Client:
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
    return client


@router.get("/clients", response_model=list[ClientOut])
def list_clients(db: Session = Depends(get_db)) -> list[Client]:
    # The scans for the risk and the last scan, in one query; never their findings (#59)
    query = (
        select(Client)
        .options(selectinload(Client.domains).selectinload(Domain.scans))
        .order_by(Client.name)
    )
    return list(db.scalars(query))


@router.post("/clients", response_model=ClientOut, status_code=status.HTTP_201_CREATED)
def create_client(payload: ClientCreate, db: Session = Depends(get_db)) -> Client:
    client = Client(name=payload.name)
    db.add(client)
    db.commit()
    db.refresh(client)
    return client


@router.get("/clients/{client_id}", response_model=ClientDetail)
def get_client(client_id: int, db: Session = Depends(get_db)) -> Client:
    return get_client_or_404(db, client_id)


@router.patch("/clients/{client_id}", response_model=ClientOut)
def rename_client(client_id: int, payload: ClientUpdate, db: Session = Depends(get_db)) -> Client:
    client = get_client_or_404(db, client_id)
    client.name = payload.name
    db.commit()
    db.refresh(client)
    return client


@router.delete("/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_client(client_id: int, db: Session = Depends(get_db)) -> Response:
    """Delete the client with all its domains, scans, findings and approvals (#16).

    This is how a client's data is erased on request (GDPR art. 17), e.g. when the MSP stops
    working for it, before the retention period of #46 would delete it.
    """
    client = get_client_or_404(db, client_id)
    refuse_while_scanning(client.domains)
    domains = len(client.domains)
    db.delete(client)
    db.commit()
    logger.info("Deleted client %s with %s domain(s)", client_id, domains)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/clients/{client_id}/domains",
    response_model=DomainOut,
    status_code=status.HTTP_201_CREATED,
)
def add_domain(
    client_id: int, payload: DomainCreate, db: Session = Depends(get_db)
) -> Domain:
    client = get_client_or_404(db, client_id)
    # A domain belongs to one client only, across all clients
    existing = db.scalar(select(Domain).where(Domain.name == payload.name))
    if existing is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{payload.name} is already added."
        )

    # The confirmation is required by DomainCreate, so a new domain is always confirmed (#3)
    domain = Domain(name=payload.name, client=client, permission_confirmed_at=datetime.now(UTC))
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain
