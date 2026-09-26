from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from qnsentry.api.schemas import (
    ClientCreate,
    ClientDetail,
    ClientOut,
    DomainCreate,
    DomainOut,
)
from qnsentry.db.models import Client, Domain
from qnsentry.db.session import get_db

router = APIRouter(prefix="/api", tags=["clients"])


def get_client_or_404(db: Session, client_id: int) -> Client:
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
    return client


@router.get("/clients", response_model=list[ClientOut])
def list_clients(db: Session = Depends(get_db)) -> list[Client]:
    query = select(Client).options(selectinload(Client.domains)).order_by(Client.name)
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


@router.post(
    "/clients/{client_id}/domains",
    response_model=DomainOut,
    status_code=status.HTTP_201_CREATED,
)
def add_domain(
    client_id: int, payload: DomainCreate, db: Session = Depends(get_db)
) -> Domain:
    client = get_client_or_404(db, client_id)
    if any(domain.name == payload.name for domain in client.domains):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This client already has this domain"
        )

    domain = Domain(name=payload.name, client=client)
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain
