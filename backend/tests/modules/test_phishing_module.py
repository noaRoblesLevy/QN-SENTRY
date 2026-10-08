"""The phishing module plugs into the worker through the Module interface."""

import pytest
from pydantic import ValidationError

from qnsentry.config import Settings, settings
from qnsentry.modules import MODULES, MODULES_BY_NAME
from qnsentry.modules.base import ScanContext
from qnsentry.modules.phishing import PhishingModule, lookalikes


def test_phishing_module_is_registered_in_the_worker_order():
    assert isinstance(MODULES_BY_NAME["phishing"], PhishingModule)
    # Contract 10.4.1: attack surface, metadata, phishing, breach
    assert [m.name for m in MODULES] == ["attack_surface", "metadata", "phishing", "breach"]


def fake_check(name, calls, result=None, error=None):
    def check(domain, *, nameservers=None, warn=None):
        calls.append((name, domain, nameservers))
        if error:
            raise error
        return result or []

    return check


LOOKALIKE = lookalikes.to_finding({"fuzzer": "homoglyph", "domain": "badsecuritylnc.be", "dns_a": ["198.51.100.23"]})


def fake_certificates(calls, result=None, error=None):
    def check(found, **kwargs):
        calls.append(("certificates", [f.asset for f in found]))
        if error:
            raise error
        return result or []

    return check


def test_run_runs_every_check_with_the_configured_resolver(monkeypatch):
    calls = []
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_domains", fake_check("lookalikes", calls, [LOOKALIKE]))
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_certificates", fake_certificates(calls))
    monkeypatch.setattr("qnsentry.modules.phishing.check_email_security", fake_check("email", calls))

    findings = PhishingModule(nameservers=["1.1.1.1"]).run(ScanContext(domain="badsecurityinc.be"))

    assert findings == [LOOKALIKE]
    assert calls == [
        ("lookalikes", "badsecurityinc.be", ["1.1.1.1"]),
        # The certificate check gets the lookalikes the first check found
        ("certificates", ["badsecuritylnc.be"]),
        ("email", "badsecurityinc.be", ["1.1.1.1"]),
    ]


def stub_checks(monkeypatch, calls):
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_domains", fake_check("lookalikes", calls, [LOOKALIKE]))
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_certificates", fake_certificates(calls))
    monkeypatch.setattr("qnsentry.modules.phishing.check_email_security", fake_check("email", calls))


def test_the_dns_servers_setting_reaches_every_dns_check(monkeypatch):
    # #80: the worker's module is created without nameservers and uses DNS_SERVERS
    calls, checked = [], []
    stub_checks(monkeypatch, calls)
    monkeypatch.setattr("qnsentry.modules.phishing.check_resolver", checked.append)
    monkeypatch.setattr(settings, "dns_servers", "1.1.1.1,9.9.9.9")

    MODULES_BY_NAME["phishing"].run(ScanContext(domain="badsecurityinc.be"))

    assert checked == [["1.1.1.1", "9.9.9.9"]]
    assert ("lookalikes", "badsecurityinc.be", ["1.1.1.1", "9.9.9.9"]) in calls
    assert ("email", "badsecurityinc.be", ["1.1.1.1", "9.9.9.9"]) in calls


def test_an_empty_dns_servers_setting_uses_the_container_dns(monkeypatch):
    calls = []
    stub_checks(monkeypatch, calls)
    monkeypatch.setattr(settings, "dns_servers", "")

    PhishingModule().run(ScanContext(domain="badsecurityinc.be"))

    assert ("lookalikes", "badsecurityinc.be", None) in calls
    assert ("email", "badsecurityinc.be", None) in calls


def test_dns_servers_a_network_blocks_fall_back_to_the_container_dns(monkeypatch):
    # Some networks block DNS to outside servers: then the container's DNS, not a failed module
    calls = []
    stub_checks(monkeypatch, calls)
    monkeypatch.setattr(settings, "dns_servers", "1.1.1.1")

    def blocked(nameservers):
        raise RuntimeError("The DNS resolver 1.1.1.1 does not resolve names that must exist (LifetimeTimeout)")

    monkeypatch.setattr("qnsentry.modules.phishing.check_resolver", blocked)
    context = ScanContext(domain="badsecurityinc.be")

    assert PhishingModule().run(context) == [LOOKALIKE]
    assert ("lookalikes", "badsecurityinc.be", None) in calls
    assert context.warnings == []


def make_settings(**values) -> Settings:
    return Settings(postgres_user="u", postgres_password="p", postgres_db="d", domain_verification_secret="s" * 40, **values)


def test_dns_servers_default_to_public_resolvers(monkeypatch):
    monkeypatch.delenv("DNS_SERVERS")
    assert make_settings().nameservers == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [(" 1.1.1.1 , 2606:4700:4700::1111 ", ["1.1.1.1", "2606:4700:4700::1111"]), ("", None), (" , ", None)],
)
def test_dns_servers_are_normalised(value, expected):
    assert make_settings(dns_servers=value).nameservers == expected


def test_a_dns_server_that_is_not_an_ip_address_is_refused():
    # A typo stops the worker with a clear error instead of failing lookups during a scan
    with pytest.raises(ValidationError, match="dns.google in DNS_SERVERS is not an IP address"):
        make_settings(dns_servers="1.1.1.1,dns.google")


def test_a_failing_check_keeps_the_findings_of_the_others(monkeypatch):
    calls = []
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_domains", fake_check("lookalikes", calls, [LOOKALIKE]))
    monkeypatch.setattr(
        "qnsentry.modules.phishing.find_lookalike_certificates",
        fake_certificates(calls, error=RuntimeError("Cert Spotter and crt.sh both failed")),
    )
    monkeypatch.setattr("qnsentry.modules.phishing.check_email_security", fake_check("email", calls))

    context = ScanContext(domain="badsecurityinc.be")

    assert PhishingModule().run(context) == [LOOKALIKE]
    # The skipped check is a warning, so it never looks like a clean result (#32)
    assert context.warnings == ["The lookalike certificates check did not run: Cert Spotter and crt.sh both failed"]


def test_no_warnings_when_every_check_ran(monkeypatch):
    calls = []
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_domains", fake_check("lookalikes", calls, [LOOKALIKE]))
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_certificates", fake_certificates(calls))
    monkeypatch.setattr("qnsentry.modules.phishing.check_email_security", fake_check("email", calls))
    context = ScanContext(domain="badsecurityinc.be")

    PhishingModule().run(context)

    assert context.warnings == []


def test_certificate_check_is_skipped_when_the_lookalike_check_fails(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "qnsentry.modules.phishing.find_lookalike_domains", fake_check("lookalikes", calls, error=RuntimeError("no DNS"))
    )
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_certificates", fake_certificates(calls))
    monkeypatch.setattr("qnsentry.modules.phishing.check_email_security", fake_check("email", calls, [LOOKALIKE]))

    context = ScanContext(domain="badsecurityinc.be")

    assert PhishingModule().run(context) == [LOOKALIKE]
    assert ("certificates", []) not in calls
    assert context.warnings == [
        "The lookalike domains check did not run: no DNS",
        "The lookalike certificates check did not run: skipped because the lookalike check failed",
    ]


def test_module_fails_when_no_check_could_run(monkeypatch):
    calls = []
    for target in ("find_lookalike_domains", "check_email_security"):
        monkeypatch.setattr(f"qnsentry.modules.phishing.{target}", fake_check(target, calls, error=RuntimeError("no DNS")))
    monkeypatch.setattr("qnsentry.modules.phishing.find_lookalike_certificates", fake_certificates(calls))

    with pytest.raises(RuntimeError, match="lookalike domains: no DNS; lookalike certificates: skipped.*; email security: no DNS"):
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
