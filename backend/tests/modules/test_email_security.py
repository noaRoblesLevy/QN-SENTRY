"""Tests for the email security check (#29). DNS answers are faked, so no network is needed."""

import dns.exception
import dns.resolver
import pytest

from qnsentry.db.models import Severity
from qnsentry.modules.phishing import email_security
from qnsentry.modules.phishing.email_security import (
    check_email_security,
    evaluate_dkim,
    evaluate_dmarc,
    evaluate_spf,
    parse_dmarc,
    spf_all_qualifier,
)

DOMAIN = "badsecurityinc.be"


# ---------- SPF ----------


def test_missing_spf_is_medium_and_lets_everyone_send():
    result = evaluate_spf(DOMAIN, ["google-site-verification=abc"])

    assert [f.severity for f in result.findings] == [Severity.MEDIUM]
    assert result.allows_everyone
    assert result.findings[0].details["check"] == "spf"


@pytest.mark.parametrize("record", ["v=spf1 +all", "v=spf1 include:_spf.example.net all"])
def test_spf_allowing_every_server_is_high(record):
    result = evaluate_spf(DOMAIN, [record])

    assert result.findings[0].severity == Severity.HIGH
    assert result.allows_everyone
    assert "can be spoofed" in result.findings[0].description


@pytest.mark.parametrize(
    ("record", "severity"),
    [
        ("v=spf1 mx ~all", Severity.LOW),
        ("v=spf1 mx ?all", Severity.MEDIUM),
        ("v=spf1 mx", Severity.MEDIUM),  # no "all": unlisted servers are neutral
    ],
)
def test_weak_spf_policies(record, severity):
    result = evaluate_spf(DOMAIN, [record])

    assert [f.severity for f in result.findings] == [severity]
    assert not result.allows_everyone


@pytest.mark.parametrize("record", ["v=spf1 mx -all", "v=spf1 redirect=_spf.example.net"])
def test_strict_or_delegated_spf_gives_no_finding(record):
    assert evaluate_spf(DOMAIN, [record]).findings == []


def test_multiple_spf_records_are_invalid():
    result = evaluate_spf(DOMAIN, ["v=spf1 mx -all", "v=spf1 a -all"])

    assert result.findings[0].severity == Severity.MEDIUM
    assert "Multiple SPF records" in result.findings[0].title


@pytest.mark.parametrize(
    ("record", "expected"),
    [("v=spf1 +all", "+all"), ("v=spf1 mx -all", "-all"), ("V=SPF1 MX ~ALL", "~all"), ("v=spf1 mx", None)],
)
def test_spf_all_qualifier(record, expected):
    assert spf_all_qualifier(record) == expected


# ---------- DMARC ----------


def test_parse_dmarc_tags():
    assert parse_dmarc("v=DMARC1; p=none; pct=50; rua=mailto:x@example.net") == {
        "v": "DMARC1",
        "p": "none",
        "pct": "50",
        "rua": "mailto:x@example.net",
    }


def test_missing_dmarc_is_medium_and_high_when_spf_allows_everyone():
    assert evaluate_dmarc(DOMAIN, [])[0].severity == Severity.MEDIUM
    assert evaluate_dmarc(DOMAIN, [], spf_allows_everyone=True)[0].severity == Severity.HIGH


def test_dmarc_none_is_more_severe_than_quarantine():
    none = evaluate_dmarc(DOMAIN, ["v=DMARC1; p=none"])[0]
    quarantine = evaluate_dmarc(DOMAIN, ["v=DMARC1; p=quarantine"])[0]

    order = list(Severity)  # info, low, medium, high, critical
    assert order.index(none.severity) > order.index(quarantine.severity)
    assert none.details["policy"] == "none"


def test_dmarc_reject_gives_no_finding_unless_partial():
    assert evaluate_dmarc(DOMAIN, ["v=DMARC1; p=reject"]) == []

    partial = evaluate_dmarc(DOMAIN, ["v=DMARC1; p=reject; pct=25"])
    assert partial[0].severity == Severity.LOW
    assert "25%" in partial[0].title


@pytest.mark.parametrize(
    "txt", [["v=DMARC1; rua=mailto:x@example.net"], ["v=DMARC1; p=none", "v=DMARC1; p=reject"]]
)
def test_invalid_or_multiple_dmarc_records_do_not_protect(txt):
    finding = evaluate_dmarc(DOMAIN, txt)[0]

    assert finding.severity == Severity.MEDIUM
    assert "spoofed" in finding.description


def test_planted_test_environment_configuration_is_detected():
    # Test environment (#2): permissive SPF and DMARC p=none on badsecurityinc.be
    spf = evaluate_spf(DOMAIN, ["v=spf1 +all"])
    dmarc = evaluate_dmarc(DOMAIN, ["v=DMARC1; p=none"], spf_allows_everyone=spf.allows_everyone)

    assert [f.severity for f in spf.findings + dmarc] == [Severity.HIGH, Severity.HIGH]
    assert all(f.type == "email_security" and f.module == "phishing" for f in spf.findings + dmarc)


# ---------- DKIM ----------


def test_dkim_keys_found_is_info_and_missing_is_low():
    found = evaluate_dkim(DOMAIN, {"selector1": "v=DKIM1; k=rsa; p=MIGf"})[0]
    missing = evaluate_dkim(DOMAIN, {})[0]

    assert found.severity == Severity.INFO
    assert found.details["selectors_found"] == ["selector1"]
    assert missing.severity == Severity.LOW
    assert "google" in missing.details["selectors_checked"]


# ---------- Full check with fake DNS ----------


class FakeTxt:
    def __init__(self, text: str):
        # Long records are split into strings of at most 255 bytes
        data = text.encode()
        self.strings = [data[i : i + 255] for i in range(0, len(data), 255)]


def fake_dns(answers: dict[str, list[str]], failing: set[str] = frozenset()):
    def resolve(self, name, rdtype):
        if name in failing or "*" in failing:
            raise dns.exception.Timeout()
        if name not in answers:
            raise dns.resolver.NXDOMAIN()
        return [FakeTxt(t) for t in answers[name]]

    return resolve


def test_full_check_of_the_test_environment(monkeypatch):
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_dns({DOMAIN: ["v=spf1 +all"], f"_dmarc.{DOMAIN}": ["v=DMARC1; p=none"]}),
    )

    findings = check_email_security(DOMAIN, nameservers=["192.0.2.53"])

    assert [(f.details["check"], f.severity) for f in findings] == [
        ("spf", Severity.HIGH),
        ("dmarc", Severity.HIGH),
        ("dkim", Severity.LOW),
    ]


def test_long_dkim_key_split_over_several_strings_is_found(monkeypatch):
    key = "v=DKIM1; k=rsa; p=" + "A" * 400
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_dns({DOMAIN: ["v=spf1 -all"], f"_dmarc.{DOMAIN}": ["v=DMARC1; p=reject"], f"google._domainkey.{DOMAIN}": [key]}),
    )

    findings = check_email_security(DOMAIN, nameservers=["192.0.2.53"])

    assert [f.title for f in findings] == [f"DKIM keys found on {DOMAIN} (google)"]


def test_one_timeout_skips_only_that_check(monkeypatch):
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_dns({DOMAIN: ["v=spf1 +all"]}, failing={f"_dmarc.{DOMAIN}"}),
    )

    checks = [f.details["check"] for f in check_email_security(DOMAIN, nameservers=["192.0.2.53"])]

    assert checks == ["spf", "dkim"]


def test_every_lookup_failing_raises(monkeypatch):
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_dns({}, failing={"*"}))

    with pytest.raises(RuntimeError, match="the SPF and DMARC lookups failed"):
        check_email_security(DOMAIN, nameservers=["192.0.2.53"])


def test_dkim_selectors_include_the_common_ones():
    assert {"default", "google", "selector1", "selector2"} <= set(email_security.DKIM_SELECTORS)
