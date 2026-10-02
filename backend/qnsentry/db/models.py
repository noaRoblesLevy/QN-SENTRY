from dataclasses import replace
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from qnsentry.risk import Risk, compute_risk


class Base(DeclarativeBase):
    pass


# Allowed values, as defined in docs/project/10-data-contract.md
class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class ModuleStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def enum_column(enum_class: type[StrEnum]) -> Enum:
    """Store the enum's value ("queued"), not its name ("QUEUED")."""
    return Enum(
        enum_class,
        native_enum=False,
        create_constraint=True,
        values_callable=lambda members: [member.value for member in members],
    )


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    domains: Mapped[list["Domain"]] = relationship(
        back_populates="client", cascade="all, delete-orphan", order_by="Domain.name"
    )

    @property
    def risk(self) -> Risk | None:
        """The client's risk: that of its riskiest domain, from each domain's latest scored scan."""
        latest = [domain.latest_risk for domain in self.domains]
        scored = [risk for risk in latest if risk is not None]
        if not scored:
            return None
        riskiest = max(scored, key=lambda risk: risk.score)
        # Incomplete when any domain's scan is: a finding missed on another domain could have
        # raised the client's score (the maximum), whichever domain is the riskiest now
        return replace(riskiest, complete=all(risk.complete for risk in scored))

    @property
    def risk_score(self) -> int | None:
        return self.risk.score if self.risk else None

    @property
    def risk_level(self) -> str | None:
        return self.risk.level if self.risk else None

    @property
    def risk_complete(self) -> bool | None:
        return self.risk.complete if self.risk else None


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE")
    )
    # A domain belongs to one client only
    name: Mapped[str] = mapped_column(String(253), unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    client: Mapped[Client] = relationship(back_populates="domains")
    # Newest scan first, as the dashboard expects
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan", order_by="Scan.id.desc()"
    )

    @property
    def latest_risk(self) -> Risk | None:
        """Risk of the newest scan that has a score (running and failed scans have none)."""
        return next((scan.risk for scan in self.scans if scan.risk is not None), None)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE")
    )
    status: Mapped[ScanStatus] = mapped_column(
        enum_column(ScanStatus), default=ScanStatus.QUEUED
    )
    context: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    domain: Mapped[Domain] = relationship(back_populates="scans")
    module_runs: Mapped[list["ModuleRun"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="ModuleRun.id"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="Finding.id"
    )

    @property
    def risk(self) -> Risk | None:
        """Risk score of the scan (#19), computed from its findings.

        Only for a finished scan: while it runs the findings are incomplete, and a failed
        scan has too few findings to mean anything (it would look safe).
        """
        if self.status not in (ScanStatus.COMPLETED, ScanStatus.PARTIAL):
            return None
        return compute_risk(
            (finding.severity for finding in self.findings),
            # A partial scan, or one with warnings, keeps its score but is flagged: a failed
            # module or a failed part of one may have missed findings
            complete=self.status == ScanStatus.COMPLETED and not any(run.warnings for run in self.module_runs),
        )

    @property
    def risk_score(self) -> int | None:
        return self.risk.score if self.risk else None

    @property
    def risk_level(self) -> str | None:
        return self.risk.level if self.risk else None

    @property
    def risk_complete(self) -> bool | None:
        return self.risk.complete if self.risk else None

    def mark_failed(self, reason: str) -> None:
        """End the scan as failed; modules that had not finished get `reason` as error."""
        finished_at = datetime.now(UTC)
        self.status = ScanStatus.FAILED
        self.finished_at = finished_at
        for module_run in self.module_runs:
            if module_run.status in (ModuleStatus.PENDING, ModuleStatus.RUNNING):
                module_run.status = ModuleStatus.FAILED
                module_run.error = reason
                module_run.finished_at = finished_at


class ModuleRun(Base):
    __tablename__ = "module_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    module: Mapped[str] = mapped_column(String(50))
    status: Mapped[ModuleStatus] = mapped_column(
        enum_column(ModuleStatus), default=ModuleStatus.PENDING
    )
    finding_count: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text)
    # Parts of the module that failed while it still had results (contract 10.3.1)
    warnings: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default=text("'[]'::jsonb"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan: Mapped[Scan] = relationship(back_populates="module_runs")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    module: Mapped[str] = mapped_column(String(50))
    type: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(enum_column(Severity))
    asset: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
