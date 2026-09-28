"""Tests for the lookalike domain module. No network: DNS results are faked as dnstwist returns them."""

from dataclasses import asdict

import dns.resolver
import pytest

from qnsentry.db.models import Severity
from qnsentry.modules.phishing.lookalikes import (
    check_resolver,
    generate_permutations,
    registered_lookalikes,
    to_finding,
)

DOMAIN = "badsecurityinc.be"


def test_generates_the_planted_homoglyph_lookalike():
    # The test environment registers badsecuritylnc.be (lowercase l instead of i)
    generated = {p["domain"]: p["fuzzer"] for p in generate_permutations(DOMAIN)}
    assert generated["badsecuritylnc.be"] == "homoglyph"


def test_untrustworthy_resolver_fails_instead_of_reporting_zero_lookalikes(monkeypatch):
    # Some resolvers answer "does not exist" for everything; that must not look like a clean result
    def deny_everything(self, name, rdtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", deny_everything)

    with pytest.raises(RuntimeError, match="does not resolve names that must exist"):
        check_resolver("be", nameservers=["192.0.2.53"])


def test_rejects_an_invalid_domain():
    with pytest.raises(ValueError, match="Not a valid domain name"):
        generate_permutations("not a domain")


def test_keeps_only_registered_lookalikes_with_mail_servers_first():
    permutations = [
        {"fuzzer": "*original", "domain": DOMAIN, "dns_a": ["203.0.113.1"]},
        {"fuzzer": "omission", "domain": "badsecurityin.be"},  # not registered
        {"fuzzer": "addition", "domain": "badsecurityinca.be", "dns_ns": ["!ServFail"]},  # lookup failed
        {"fuzzer": "hyphenation", "domain": "bad-securityinc.be", "dns_a": ["198.51.100.7"]},
        {"fuzzer": "homoglyph", "domain": "badsecuritylnc.be", "dns_mx": ["mail.badsecuritylnc.be"]},
    ]

    found = [p["domain"] for p in registered_lookalikes(DOMAIN, permutations)]

    assert found == ["badsecuritylnc.be", "bad-securityinc.be"]


def test_lookalike_with_mail_server_is_high():
    finding = to_finding(
        {
            "fuzzer": "homoglyph",
            "domain": "badsecuritylnc.be",
            "dns_ns": ["ns1.example-dns.net"],
            "dns_a": ["198.51.100.23"],
            "dns_mx": ["mail.badsecuritylnc.be"],
        }
    )

    assert finding.severity == Severity.HIGH
    assert finding.module == "phishing"
    assert finding.type == "lookalike_domain"
    assert finding.asset == "badsecuritylnc.be"
    assert "can receive email" in finding.title
    assert finding.details["mx"] == ["mail.badsecuritylnc.be"]
    assert finding.details["fuzzer"] == "homoglyph"


@pytest.mark.parametrize("mx", [[], ["!ServFail"], [""]], ids=["no MX", "failed lookup", "null MX"])
def test_lookalike_without_working_mail_server_is_low(mx):
    finding = to_finding({"fuzzer": "hyphenation", "domain": "bad-securityinc.be", "dns_a": ["198.51.100.7"], "dns_mx": mx})

    assert finding.severity == Severity.LOW
    assert finding.details["mx"] == []


def test_unicode_homoglyph_is_readable_in_the_title():
    finding = to_finding({"fuzzer": "homoglyph", "domain": "xn--bdsecurityinc-bfb.be", "dns_a": ["198.51.100.9"]})

    assert finding.asset == "xn--bdsecurityinc-bfb.be"
    assert finding.details["unicode"] == "bädsecurityinc.be"
    assert "bädsecurityinc.be" in finding.title


def test_finding_serialises_to_the_data_contract_fields():
    data = asdict(to_finding({"fuzzer": "homoglyph", "domain": "badsecuritylnc.be", "dns_a": ["198.51.100.23"]}))

    assert set(data) == {"module", "type", "title", "description", "severity", "asset", "details"}
    assert data["severity"] == "low"
