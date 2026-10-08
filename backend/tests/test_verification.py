"""Domain ownership verification with a TXT record (#48). DNS is faked, no network needed."""

import dns.exception
import dns.resolver
import pytest
from pydantic import ValidationError

from qnsentry import verification
from qnsentry.config import EXAMPLE_SECRET, Settings
from qnsentry.verification import (
    PREFIX,
    VerificationLookupFailed,
    has_verification_record,
    txt_records,
    verification_record,
    verification_token,
)

SECRET = "a" * 40


def test_token_is_stable_for_the_same_secret_and_domain():
    # The same secret gives the same record after the database is emptied or on a new laptop
    assert verification_token("badsecurityinc.be", SECRET) == verification_token("badsecurityinc.be", SECRET)
    assert verification_token("BadSecurityInc.be.", SECRET) == verification_token("badsecurityinc.be", SECRET)


def test_token_differs_per_domain_and_per_installation():
    token = verification_token("badsecurityinc.be", SECRET)

    assert verification_token("badsecuritylnc.be", SECRET) != token
    # Another installation (another secret) needs its own record
    assert verification_token("badsecurityinc.be", "b" * 40) != token
    assert len(token) == verification.TOKEN_LENGTH and int(token, 16) >= 0


def test_record_format():
    record = verification_record("badsecurityinc.be", SECRET)

    assert record.startswith(PREFIX)
    assert record == f"qn-sentry-verify={verification_token('badsecurityinc.be', SECRET)}"


@pytest.mark.parametrize(
    "shown", ['"{r}"', " {r} ", "{r}"], ids=["with quotes", "with spaces", "exact"]
)
def test_record_is_found_among_other_txt_records(shown):
    record = verification_record("badsecurityinc.be", SECRET)
    records = ["v=spf1 +all", shown.format(r=record), "google-site-verification=abc"]

    assert has_verification_record(records, record)


def test_a_different_or_partial_record_does_not_verify():
    record = verification_record("badsecurityinc.be", SECRET)

    assert not has_verification_record([], record)
    assert not has_verification_record([verification_record("badsecurityinc.be", "b" * 40)], record)
    assert not has_verification_record([record[:-1]], record)
    assert not has_verification_record([f"{record} extra"], record)


class FakeTxt:
    def __init__(self, text):
        # dnspython splits long TXT values into strings of at most 255 bytes
        self.strings = [text[i : i + 255].encode() for i in range(0, len(text), 255)]


def fake_resolve(answers=None, error=None):
    def resolve(self, name, rdtype):
        assert rdtype == "TXT"
        if error:
            raise error
        if name not in (answers or {}):
            raise dns.resolver.NXDOMAIN()
        return [FakeTxt(t) for t in answers[name]]

    return resolve


def test_txt_records_joins_split_strings(monkeypatch):
    long_value = "x" * 300
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve({"badsecurityinc.be": ["v=spf1 +all", long_value]}))

    assert txt_records("badsecurityinc.be", nameservers=["192.0.2.53"]) == ["v=spf1 +all", long_value]


@pytest.mark.parametrize("error", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()], ids=["no domain", "no TXT"])
def test_missing_records_are_an_empty_list(monkeypatch, error):
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve(error=error))

    assert txt_records("badsecurityinc.be", nameservers=["192.0.2.53"]) == []


def test_a_failed_lookup_is_not_treated_as_missing(monkeypatch):
    # A timeout must not tell the user "record not found"
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve(error=dns.exception.Timeout()))

    with pytest.raises(VerificationLookupFailed, match="Timeout"):
        txt_records("badsecurityinc.be", nameservers=["192.0.2.53"])


@pytest.mark.parametrize("secret", ["too-short", EXAMPLE_SECRET], ids=["too short", "the public example"])
def test_a_weak_secret_is_refused(secret):
    with pytest.raises(ValidationError, match="domain_verification_secret"):
        Settings(postgres_user="u", postgres_password="p", postgres_db="d", domain_verification_secret=secret)


def test_a_refused_secret_is_not_printed_in_the_error():
    # The error ends up in the container logs; a real secret that is one character too short
    # must not appear there
    secret = "almost-a-real-secret-but-too-short"[:31]

    with pytest.raises(ValidationError) as error:
        Settings(postgres_user="u", postgres_password="p", postgres_db="d", domain_verification_secret=secret)

    assert "domain_verification_secret" in str(error.value)
    assert secret not in str(error.value)
