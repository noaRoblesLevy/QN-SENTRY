"""The phishing module plugs into the worker through the Module interface."""

from qnsentry.modules import MODULES, MODULES_BY_NAME
from qnsentry.modules.base import ScanContext
from qnsentry.modules.phishing import PhishingModule, lookalikes


def test_phishing_module_is_registered_in_the_worker_order():
    assert isinstance(MODULES_BY_NAME["phishing"], PhishingModule)
    # Contract 10.4.1: attack surface, metadata, phishing, breach
    assert [m.name for m in MODULES] == ["attack_surface", "metadata", "phishing", "breach"]


def test_run_checks_the_scanned_domain_with_the_configured_resolver(monkeypatch):
    calls = []

    def fake_find(domain, *, nameservers=None):
        calls.append((domain, nameservers))
        return []

    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_domains", fake_find)

    findings = PhishingModule(nameservers=["1.1.1.1"]).run(ScanContext(domain="badsecurityinc.be"))

    assert findings == []
    assert calls == [("badsecurityinc.be", ["1.1.1.1"])]


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
