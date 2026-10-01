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
    # Risk score (#19); null while the scan runs or when it failed
    risk_score: int | None = None
    risk_level: str | None = None
    # False when the score comes from a partial scan (a module failed)
    risk_complete: bool | None = None


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
    # Risk of the riskiest domain (#19); null when no domain has a finished scan
    risk_score: int | None = None
    risk_level: str | None = None
    # False when the score comes from a partial scan (a module failed)
    risk_complete: bool | None = None


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
    # Risk score (#19); null while the scan runs or when it failed
    risk_score: int | None = None
    risk_level: str | None = None
    # False when the score comes from a partial scan (a module failed)
    risk_complete: bool | None = None


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
