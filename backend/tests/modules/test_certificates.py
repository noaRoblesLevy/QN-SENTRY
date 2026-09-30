"""Tests for lookalike certificates from Certificate Transparency (#10). No network needed."""

from datetime import UTC, datetime

import pytest

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding
from qnsentry.modules.phishing import certificates
from qnsentry.modules.phishing.certificates import (
    find_lookalike_certificates,
    parse_certspotter,
    parse_crtsh,
)

NOW = datetime(2026, 10, 1, tzinfo=UTC)

# The real Cert Spotter answer for badsecuritylnc.be on 30/09/2026 (shortened)
CERTSPOTTER = [
    {
        "id": "17495527067",
        "cert_sha256": "b05ce9cda34a84ae63a84a0d799eac9c1ad4f67695e81cc51d3a937dfd486bb9",
        "dns_names": ["badsecuritylnc.be"],
        "issuer": {"friendly_name": "Let's Encrypt", "name": "C=US, O=Let's Encrypt, CN=YR1"},
        "not_before": "2026-09-30T06:27:21Z",
        "not_after": "2026-12-29T06:27:20Z",
        "revoked": False,
    }
]

# crt.sh lists the precertificate and the final certificate as two entries
CRTSH = [
    {
        "id": 1001,
        "issuer_name": "C=US, O=Let's Encrypt, CN=YR1",
        "name_value": "badsecuritylnc.be\nwww.badsecuritylnc.be",
        "not_before": "2026-09-30T06:27:21",
        "not_after": "2026-12-29T06:27:20",
    },
    {
        "id": 1002,
        "issuer_name": "C=US, O=Let's Encrypt, CN=YR1",
        "name_value": "www.badsecuritylnc.be\nbadsecuritylnc.be",
        "not_before": "2026-09-30T06:27:21",
        "not_after": "2026-12-29T06:27:20",
    },
]


def lookalike(name="badsecuritylnc.be", severity=Severity.HIGH) -> Finding:
    return Finding(
        module="phishing",
        type="lookalike_domain",
        title=f"Registered lookalike domain {name}",
        description="",
        severity=severity,
        asset=name,
    )


# ---------- Parsing ----------


def test_parse_certspotter():
    [cert] = parse_certspotter(CERTSPOTTER)

    assert cert.names == ("badsecuritylnc.be",)
    assert cert.issuer == "Let's Encrypt"
    assert cert.not_before == datetime(2026, 9, 30, 6, 27, 21, tzinfo=UTC)
    assert cert.source == "Cert Spotter"
    assert cert.reference.startswith("https://crt.sh/?sha256=b05ce9")


def test_parse_crtsh_merges_the_precertificate_and_certificate():
    [cert] = parse_crtsh(CRTSH)

    assert cert.names == ("badsecuritylnc.be", "www.badsecuritylnc.be")
    assert cert.issuer == "Let's Encrypt"
    assert cert.not_after == datetime(2026, 12, 29, 6, 27, 20, tzinfo=UTC)
    assert cert.source == "crt.sh"


# ---------- Findings ----------


def use_services(monkeypatch, certspotter=None, crtsh=None):
    """Replace both CT services: a list is their answer, an exception is raised."""

    def fake(answer, parse):
        def fetch(domain):
            if isinstance(answer, Exception):
                raise answer
            return parse(answer or [])

        return fetch

    monkeypatch.setattr(certificates, "from_certspotter", fake(certspotter, parse_certspotter))
    monkeypatch.setattr(certificates, "from_crtsh", fake(crtsh, parse_crtsh))


def test_valid_certificate_for_a_lookalike_is_high(monkeypatch):
    use_services(monkeypatch, certspotter=CERTSPOTTER)

    [finding] = find_lookalike_certificates([lookalike()], now=NOW)

    assert finding.type == "lookalike_certificate"
    assert finding.module == "phishing"
    assert finding.asset == "badsecuritylnc.be"
    assert finding.severity == Severity.HIGH
    assert "issued by Let's Encrypt on 2026-09-30" in finding.description
    assert finding.details["valid_now"] is True
    assert finding.details["certificates"][0]["source"] == "Cert Spotter"


def test_expired_certificate_is_medium(monkeypatch):
    use_services(monkeypatch, certspotter=CERTSPOTTER)

    [finding] = find_lookalike_certificates([lookalike()], now=datetime(2027, 6, 1, tzinfo=UTC))

    assert finding.severity == Severity.MEDIUM
    assert finding.title.startswith("Expired TLS certificate")


def test_certificate_for_the_companys_own_lookalike_is_info(monkeypatch):
    use_services(monkeypatch, certspotter=CERTSPOTTER)

    [finding] = find_lookalike_certificates([lookalike(severity=Severity.INFO)], now=NOW)

    assert finding.severity == Severity.INFO


def test_lookalike_without_certificates_gives_no_finding(monkeypatch):
    use_services(monkeypatch, certspotter=[])

    assert find_lookalike_certificates([lookalike()], now=NOW) == []


def test_crtsh_is_used_when_cert_spotter_fails(monkeypatch):
    use_services(monkeypatch, certspotter=OSError("HTTP Error 429: Too Many Requests"), crtsh=CRTSH)

    [finding] = find_lookalike_certificates([lookalike()], now=NOW)

    assert finding.details["certificates"][0]["source"] == "crt.sh"


def test_fails_when_both_services_fail_for_every_lookalike(monkeypatch):
    use_services(monkeypatch, certspotter=OSError("timed out"), crtsh=OSError("HTTP Error 502: Bad Gateway"))

    with pytest.raises(RuntimeError, match="both failed"):
        find_lookalike_certificates([lookalike()], now=NOW)


def test_no_lookalikes_means_no_requests(monkeypatch):
    def must_not_be_called(domain):
        raise AssertionError("no CT request expected")

    monkeypatch.setattr(certificates, "from_certspotter", must_not_be_called)
    monkeypatch.setattr(certificates, "from_crtsh", must_not_be_called)

    assert find_lookalike_certificates([], now=NOW) == []
    # Other finding types (e.g. email security) are not looked up either
    other = Finding(module="phishing", type="email_security", title="", description="", severity=Severity.HIGH, asset="x")
    assert find_lookalike_certificates([other], now=NOW) == []
