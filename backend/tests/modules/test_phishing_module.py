"""The phishing module plugs into the worker through the Module interface."""

import pytest

from qnsentry.modules import MODULES, MODULES_BY_NAME
from qnsentry.modules.base import ScanContext
from qnsentry.modules.phishing import PhishingModule, lookalikes


def test_phishing_module_is_registered_in_the_worker_order():
    assert isinstance(MODULES_BY_NAME["phishing"], PhishingModule)
    # Contract 10.4.1: attack surface, metadata, phishing, breach
    assert [m.name for m in MODULES] == ["attack_surface", "metadata", "phishing", "breach"]


def fake_check(name, calls, result=None, error=None):
    def check(domain, *, nameservers=None):
        calls.append((name, domain, nameservers))
        if error:
            raise error
        return result or []

    return check


def test_run_runs_every_check_on_the_scanned_domain_with_the_configured_resolver(monkeypatch):
    calls = []
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_domains", fake_check("lookalikes", calls))
    monkeypatch.setattr("qnsentry.modules.phishing.check_email_security", fake_check("email", calls))

    findings = PhishingModule(nameservers=["1.1.1.1"]).run(ScanContext(domain="badsecurityinc.be"))

    assert findings == []
    assert calls == [
        ("lookalikes", "badsecurityinc.be", ["1.1.1.1"]),
        ("email", "badsecurityinc.be", ["1.1.1.1"]),
    ]


def test_a_failing_check_keeps_the_findings_of_the_others(monkeypatch):
    calls = []
    finding = lookalikes.to_finding({"fuzzer": "homoglyph", "domain": "badsecuritylnc.be", "dns_a": ["198.51.100.23"]})
    monkeypatch.setattr(
        "qnsentry.modules.phishing.find_lookalike_domains",
        fake_check("lookalikes", calls, error=RuntimeError("resolver down")),
    )
    monkeypatch.setattr("qnsentry.modules.phishing.check_email_security", fake_check("email", calls, [finding]))

    assert PhishingModule().run(ScanContext(domain="badsecurityinc.be")) == [finding]


def test_module_fails_when_every_check_fails(monkeypatch):
    calls = []
    for target in ("find_lookalike_domains", "check_email_security"):
        monkeypatch.setattr(
            f"qnsentry.modules.phishing.{target}", fake_check(target, calls, error=RuntimeError("no DNS"))
        )

    with pytest.raises(RuntimeError, match="lookalike domains: no DNS; email security: no DNS"):
        PhishingModule().run(ScanContext(domain="badsecurityinc.be"))


def test_findings_can_be_stored_by_the_worker():
    # The worker stores findings with models.Finding(**asdict(finding))
    from dataclasses import asdict

    from qnsentry.db import models

    finding = lookalikes.to_finding(
        {"fuzzer": "homoglyph", "domain": "badsecuritylnc.be", "dns_mx": ["mail.badsecuritylnc.be"]}
    )
    row = models.Finding(**asdict(finding))

    assert row.severity == "high"
    assert row.module == "phishing"
