"""Request and response bodies of the API (docs/project/10-data-contract.md, 10.5)."""

import ipaddress
import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

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
    # The user confirms they own the domain or have written permission to scan it (#3)
    # validate_default: the check must also run when the field is left out
    # StrictBool: a confirmation with legal weight only counts as the JSON value true,
    # not as "yes" or 1
    permission_confirmed: StrictBool = Field(False, validate_default=True)

    @field_validator("permission_confirmed")
    @classmethod
    def require_permission(cls, value: bool) -> bool:
        if not value:
            raise ValueError("Confirm that you own this domain or have written permission to scan it.")
        return value

    @field_validator("name")
    @classmethod
    def normalise_domain(cls, value: str) -> str:
        domain = value.lower().rstrip(".")
        if not DOMAIN_PATTERN.match(domain):
            raise ValueError("Enter a valid domain name, e.g. example.be")
        return domain


class PortScanApprovalsIn(BaseModel):
    """The addresses of a domain the user confirms may get a port scan (#81)."""

    ips: list[str]

    @field_validator("ips")
    @classmethod
    def valid_addresses(cls, value: list[str]) -> list[str]:
        normalised = []
        for ip in value:
            try:
                address = str(ipaddress.ip_address(ip.strip()))
            except ValueError:
                raise ValueError(f"{ip} is not a valid IP address.") from None
            if address not in normalised:
                normalised.append(address)
        return normalised


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
    # Permission (#3) and ownership (#48): a scan needs both
    permission_confirmed: bool
    verified: bool
    # The TXT record to add to the domain, e.g. "qn-sentry-verify=3f9a..."
    verification_record: str
    # Addresses the user confirmed may get a port scan (#81)
    port_scan_ips: list[str]


class AddressOut(BaseModel):
    """An address of a domain's hosts, and whether it may get a port scan (#81)."""

    ip: str
    # Host names that resolved to it in the latest scan; [] for an approved address the
    # latest scan did not see anymore
    hosts: list[str]
    approved: bool


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
    # Parts that failed while the module still had results; [] when there are none
    warnings: list[str]


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
