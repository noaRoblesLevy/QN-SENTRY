"""Tests for lookalike certificates from Certificate Transparency (#10). No network needed."""

import http.client
from datetime import UTC, datetime

import pytest

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding
from qnsentry.modules.phishing import certificates
from qnsentry.modules.phishing.certificates import (
    MAX_FAILURES_IN_A_ROW,
    certificates_for,
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
    """Replace both CT services: a list is their answer, an exception is raised.
    Returns the calls per service."""
    calls = {"Cert Spotter": [], "crt.sh": []}

    def fake(service, answer, parse):
        def fetch(domain, **kwargs):
            calls[service].append((domain, kwargs))
            if isinstance(answer, Exception):
                raise answer
            return parse(answer or [])

        return fetch

    monkeypatch.setattr(certificates, "from_certspotter", fake("Cert Spotter", certspotter, parse_certspotter))
    monkeypatch.setattr(certificates, "from_crtsh", fake("crt.sh", crtsh, parse_crtsh))
    return calls


def test_valid_certificate_for_a_lookalike_is_high(monkeypatch):
    use_services(monkeypatch, certspotter=CERTSPOTTER)

    [finding] = find_lookalike_certificates([lookalike()], now=NOW)

    assert finding.type == "lookalike_certificate"
    assert finding.module == "phishing"
    assert finding.asset == "badsecuritylnc.be"
    assert finding.severity == Severity.HIGH
    assert "issued by Let's Encrypt on 2026-09-30" in finding.description
    assert finding.details["source"] == "Cert Spotter"
    assert finding.details["certificates"][0]["source"] == "Cert Spotter"


@pytest.mark.parametrize("service", ["certspotter", "crtsh"])
def test_only_valid_certificates_count_whichever_service_answers(monkeypatch, service):
    # Cert Spotter only lists unexpired certificates; crt.sh is asked the same, so the
    # result never depends on which service answered
    if service == "certspotter":
        use_services(monkeypatch, certspotter=CERTSPOTTER)
    else:
        use_services(monkeypatch, certspotter=OSError("HTTP Error 429"), crtsh=CRTSH)

    assert find_lookalike_certificates([lookalike()], now=datetime(2027, 6, 1, tzinfo=UTC)) == []


def test_crtsh_is_asked_for_unexpired_certificates_only():
    assert "exclude=expired" in certificates.CRTSH_URL


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

    with pytest.raises(RuntimeError, match="could not be searched reliably"):
        find_lookalike_certificates([lookalike()], now=NOW)


def test_cert_spotter_failing_and_an_empty_crtsh_answer_is_uncertain_not_clean(monkeypatch):
    # Reviewer's probe: 14 hours after issuance crt.sh still had nothing for badsecuritylnc.be
    use_services(monkeypatch, certspotter=OSError("HTTP Error 429"), crtsh=[])

    with pytest.raises(certificates.CertificateLookupFailed, match="can take hours to index"):
        certificates_for("badsecuritylnc.be")
    with pytest.raises(RuntimeError, match="could not be searched reliably"):
        find_lookalike_certificates([lookalike()], now=NOW)


def test_an_empty_cert_spotter_answer_is_trusted(monkeypatch):
    use_services(monkeypatch, certspotter=[])

    assert certificates_for("badsecuritylnc.be") == []


def test_one_uncertain_lookalike_does_not_hide_the_others(monkeypatch):
    def certspotter(domain, **kwargs):
        if domain == "badsecuritylnc.be":
            raise OSError("HTTP Error 503")
        return parse_certspotter(CERTSPOTTER)

    monkeypatch.setattr(certificates, "from_certspotter", certspotter)
    monkeypatch.setattr(certificates, "from_crtsh", lambda domain: [])

    found = find_lookalike_certificates([lookalike(), lookalike("bad-securityinc.be")], now=NOW)

    assert [f.asset for f in found] == ["bad-securityinc.be"]


def test_a_failing_service_is_skipped_after_three_failures_in_a_row(monkeypatch):
    calls = use_services(monkeypatch, certspotter=OSError("timed out"), crtsh=OSError("HTTP Error 502"))
    domains = [lookalike(f"lookalike{i}.be") for i in range(10)]

    with pytest.raises(RuntimeError):
        find_lookalike_certificates(domains, now=NOW)

    # Without the circuit breaker: 10 x 2 requests of up to 30 s each
    assert len(calls["Cert Spotter"]) == MAX_FAILURES_IN_A_ROW
    assert len(calls["crt.sh"]) == MAX_FAILURES_IN_A_ROW


def test_a_success_resets_the_failure_count(monkeypatch):
    answers = iter([OSError("x"), OSError("x"), CERTSPOTTER, OSError("x"), OSError("x"), CERTSPOTTER])

    def certspotter(domain, **kwargs):
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return parse_certspotter(answer)

    monkeypatch.setattr(certificates, "from_certspotter", certspotter)
    monkeypatch.setattr(certificates, "from_crtsh", lambda domain: parse_crtsh(CRTSH))

    found = find_lookalike_certificates([lookalike(f"l{i}.be") for i in range(6)], now=NOW)

    assert len(found) == 6  # four answered by crt.sh, two by Cert Spotter: never skipped


def test_the_api_key_is_sent_to_cert_spotter(monkeypatch):
    calls = use_services(monkeypatch, certspotter=CERTSPOTTER)

    find_lookalike_certificates([lookalike()], now=NOW, api_key="secret")

    assert calls["Cert Spotter"] == [("badsecuritylnc.be", {"api_key": "secret"})]


def test_bearer_header_only_with_a_key(monkeypatch):
    sent = []
    monkeypatch.setattr(certificates, "_get_json", lambda url, headers=None: sent.append(headers) or [])

    certificates.from_certspotter("badsecuritylnc.be", api_key="secret")
    certificates.from_certspotter("badsecuritylnc.be")

    assert sent == [{"Authorization": "Bearer secret"}, {}]


def test_no_lookalikes_means_no_requests(monkeypatch):
    def must_not_be_called(domain):
        raise AssertionError("no CT request expected")

    monkeypatch.setattr(certificates, "from_certspotter", must_not_be_called)
    monkeypatch.setattr(certificates, "from_crtsh", must_not_be_called)

    assert find_lookalike_certificates([], now=NOW) == []
    # Other finding types (e.g. email security) are not looked up either
    other = Finding(module="phishing", type="email_security", title="", description="", severity=Severity.HIGH, asset="x")
    assert find_lookalike_certificates([other], now=NOW) == []


# Reviewer's probe on #49: an incomplete answer is an http.client.HTTPException, not an OSError


@pytest.mark.parametrize(
    "error",
    [http.client.IncompleteRead(b"[{"), ConnectionResetError("reset"), ValueError("HTML instead of JSON")],
    ids=["incomplete answer", "connection reset", "not JSON"],
)
def test_an_error_for_one_lookalike_skips_only_that_lookalike(monkeypatch, error):
    def certspotter(domain, **kwargs):
        if domain == "b.be":
            raise error
        return parse_certspotter(CERTSPOTTER)

    monkeypatch.setattr(certificates, "from_certspotter", certspotter)
    monkeypatch.setattr(certificates, "from_crtsh", lambda domain: [])
    warnings = []

    found = find_lookalike_certificates(
        [lookalike("a.be"), lookalike("b.be"), lookalike("c.be")], now=NOW, warn=warnings.append
    )

    assert [f.asset for f in found] == ["a.be", "c.be"]
    assert warnings == [
        "1 of 3 lookalike domain(s) could not be checked for certificates, so certificates for them may have been missed"
    ]


def test_lookalikes_above_the_limit_are_a_warning(monkeypatch):
    use_services(monkeypatch, certspotter=[])
    warnings = []

    find_lookalike_certificates(
        [lookalike(f"l{i}.be") for i in range(certificates.MAX_LOOKALIKES + 5)], now=NOW, warn=warnings.append
    )

    assert warnings == [
        f"Only the first {certificates.MAX_LOOKALIKES} of {certificates.MAX_LOOKALIKES + 5} lookalike domains were "
        "checked for certificates (those that can receive email first)"
    ]

