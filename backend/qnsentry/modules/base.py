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


class Module(ABC):
    """Base class for an OSINT module (contract 10.3).

    A module reads the scan context, may add information to it for later
    modules, and returns its findings. It never writes to the database:
    the worker stores the findings.
    """

    name: str

    @abstractmethod
    def run(self, context: ScanContext) -> list[Finding]:
        """Run the module. Raise an exception if it cannot run at all."""
