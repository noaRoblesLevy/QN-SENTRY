"""The worker runs the modules of a scan and stores findings and warnings (contract 10.3)."""

import os

import pytest

# The worker reads Settings when it is imported; these tests need no real database
for name, value in {"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "test"}.items():
    os.environ.setdefault(name, value)

from qnsentry.db import models  # noqa: E402
from qnsentry.db.models import ModuleStatus, ScanStatus, Severity  # noqa: E402
from qnsentry.modules.base import Finding, Module, ScanContext  # noqa: E402
from qnsentry.worker import tasks  # noqa: E402


class FakeSession:
    """Enough of a SQLAlchemy session for run_modules: it only adds and commits."""

    def __init__(self):
        self.added = []

    def add(self, item):
        self.added.append(item)

    def commit(self):
        pass


class FakeModule(Module):
    def __init__(self, name, warnings=(), error=None, findings=()):
        self.name, self.warnings, self.error, self.findings = name, warnings, error, findings
        self.seen_warnings = None

    def run(self, context: ScanContext) -> list[Finding]:
        self.seen_warnings = list(context.warnings)
        for warning in self.warnings:
            context.warn(warning)
        if self.error:
            raise self.error
        return list(self.findings)


def run(monkeypatch, *modules):
    monkeypatch.setattr(tasks, "MODULES_BY_NAME", {m.name: m for m in modules})
    scan = models.Scan(
        id=1,
        domain=models.Domain(name="badsecurityinc.be"),
        module_runs=[models.ModuleRun(module=m.name, status=ModuleStatus.PENDING) for m in modules],
    )
    tasks.run_modules(FakeSession(), scan)
    return scan


def finding(title="x"):
    return Finding(module="a", type="t", title=title, description="d", severity=Severity.LOW, asset="a")


def test_warnings_are_stored_per_module_run(monkeypatch):
    scan = run(
        monkeypatch,
        FakeModule("a", warnings=["crt.sh timed out"], findings=[finding()]),
        FakeModule("b"),
    )

    assert [run.warnings for run in scan.module_runs] == [["crt.sh timed out"], []]
    # A warning does not change the status: the module still had results
    assert [run.status for run in scan.module_runs] == [ModuleStatus.COMPLETED, ModuleStatus.COMPLETED]
    assert scan.status == ScanStatus.COMPLETED


def test_each_module_starts_with_no_warnings(monkeypatch):
    second = FakeModule("b")
    run(monkeypatch, FakeModule("a", warnings=["first module's problem"]), second)

    assert second.seen_warnings == []


def test_warnings_are_kept_when_the_module_fails_afterwards(monkeypatch):
    scan = run(monkeypatch, FakeModule("a", warnings=["3 documents could not be downloaded"], error=RuntimeError("boom")))

    [module_run] = scan.module_runs
    assert module_run.status == ModuleStatus.FAILED
    assert module_run.error == "boom"
    assert module_run.warnings == ["3 documents could not be downloaded"]
    assert scan.status == ScanStatus.PARTIAL


def test_warnings_are_not_stored_in_the_scan_context(monkeypatch):
    scan = run(monkeypatch, FakeModule("a", warnings=["something"]))

    assert "warnings" not in scan.context
    assert scan.context["domain"] == "badsecurityinc.be"


def test_duplicate_and_empty_warnings_are_dropped_in_order():
    assert tasks.limit_warnings(["b", "a", "b", "", "  ", " a "]) == ["b", "a"]


def test_many_warnings_are_summarised():
    warnings = [f"document {i} could not be read" for i in range(50)]

    limited = tasks.limit_warnings(warnings)

    assert len(limited) == tasks.MAX_WARNINGS
    assert limited[:-1] == warnings[: tasks.MAX_WARNINGS - 1]
    assert limited[-1] == "... and 31 more warnings"


@pytest.mark.parametrize("count", [tasks.MAX_WARNINGS - 1, tasks.MAX_WARNINGS])
def test_up_to_the_limit_nothing_is_summarised(count):
    warnings = [f"w{i}" for i in range(count)]
    assert tasks.limit_warnings(warnings) == warnings
