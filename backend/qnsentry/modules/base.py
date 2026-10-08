"""Module interface shared by all OSINT modules (docs/project/10-data-contract.md)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from qnsentry.db.models import Severity


@dataclass
class Finding:
    """One thing a module discovers (contract 10.1)."""

    module: str
    type: str
    title: str
    description: str
    severity: Severity
    asset: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    """Information shared between the modules of one scan (contract 10.4)."""

    domain: str
    person_names: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    email_convention: str | None = None
    # Hosts of the domain that resolve, from Attack Surface (#4) for its port and web checks:
    # [{"name": "www.example.be", "ips": ["192.0.2.10"]}]
    live_hosts: list[dict] = field(default_factory=list)
    # Addresses the user confirmed may get a port scan (#81), set by the worker from the
    # domain; an address that is not in this list is never port-scanned
    port_scan_ips: list[str] = field(default_factory=list)
    # How a last name of several words is written: "joined" or "separated" (contract 10.4.3)
    last_name_style: str | None = None
    # Warnings of the module that is running; the worker empties the list before each module
    # and stores it with that module's run. Not shared between modules, not stored in the scan.
    warnings: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        """Report that a part of the module failed while it still has results (contract 10.3.1).

        One readable sentence per kind of problem, with a count instead of one warning per
        item, and without personal data: warnings are shown in the dashboard and the report.
        """
        self.warnings.append(message)


class Module(ABC):
    """Base class for an OSINT module (contract 10.3).

    A module reads the scan context, may add information to it for later
    modules, and returns its findings. It never writes to the database:
    the worker stores the findings. When a part of it fails but it still has
    results, it calls context.warn() instead of raising.
    """

    name: str

    @abstractmethod
    def run(self, context: ScanContext) -> list[Finding]:
        """Run the module. Raise an exception if it cannot run at all."""
