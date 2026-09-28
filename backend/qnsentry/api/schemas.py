"""Request and response bodies of the API (docs/project/10-data-contract.md, 10.5)."""

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from qnsentry.db.models import ModuleStatus, ScanStatus, Severity

# One or more labels of letters, digits and hyphens, followed by a top-level domain
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


# ---------- Request bodies ----------


class ClientCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=200)


class DomainCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str

    @field_validator("name")
    @classmethod
    def normalise_domain(cls, value: str) -> str:
        domain = value.lower().rstrip(".")
        if not DOMAIN_PATTERN.match(domain):
            raise ValueError("Enter a valid domain name, e.g. example.be")
        return domain


# ---------- Response bodies ----------


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: ScanStatus
    created_at: datetime


class DomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class DomainWithScans(DomainOut):
    scans: list[ScanSummary]


class ClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    domains: list[DomainOut]


class ClientDetail(ClientOut):
    domains: list[DomainWithScans]


class ModuleRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    module: str
    status: ModuleStatus
    finding_count: int
    error: str | None


class ScanOut(BaseModel):
    id: int
    domain: str
    status: ScanStatus
    created_at: datetime
    modules: list[ModuleRunOut]


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    module: str
    type: str
    title: str
    description: str
    severity: Severity
    asset: str
    details: dict[str, Any]
    created_at: datetime
