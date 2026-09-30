"""Tests for the Breach module and its local dataset source (#11). No network needed."""

import io
import json
import urllib.error
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from qnsentry.db.models import Severity
from qnsentry.modules import MODULES_BY_NAME
from qnsentry.modules.base import ScanContext
from qnsentry.modules.breach import BreachModule, to_finding
from qnsentry.modules.breach.sources import (
    DEFAULT_DATASET,
    Breach,
    BreachSource,
    HibpSource,
    LocalDatasetSource,
    get_breach_source,
)

SHOP = Breach("ExampleShop", "2021-06-22", ("Email addresses", "Passwords"))
FORUM = Breach("FictionalBikeForum", "2019-03-10", ("Email addresses", "Usernames"))


class FakeSource(BreachSource):
    def __init__(self, accounts: dict[str, list[Breach]]):
        self.accounts = accounts
        self.looked_up: list[str] = []

    def lookup(self, email: str) -> list[Breach]:
        self.looked_up.append(email)
        return self.accounts.get(email, [])


def write_dataset(tmp_path, data) -> str:
    path = tmp_path / "breaches.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


# ---------- Local dataset source ----------


def test_local_source_looks_up_addresses_case_insensitively(tmp_path):
    path = write_dataset(
        tmp_path,
        {
            "breaches": {"ExampleShop": {"date": "2021-06-22", "data_classes": ["Email addresses", "Passwords"]}},
            "accounts": {"Jan.Peeters@BadSecurityInc.be": ["ExampleShop"]},
        },
    )
    source = LocalDatasetSource(path)

    assert source.lookup(" jan.peeters@badsecurityinc.be ") == [SHOP]
    assert source.lookup("emma.claes@badsecurityinc.be") == []


def test_local_source_rejects_an_account_with_an_unknown_breach(tmp_path):
    path = write_dataset(tmp_path, {"breaches": {}, "accounts": {"a@badsecurityinc.be": ["Nope"]}})

    with pytest.raises(RuntimeError, match="unknown breaches"):
        LocalDatasetSource(path)


def test_missing_dataset_fails_the_module_clearly(tmp_path):
    with pytest.raises(RuntimeError, match="could not be read"):
        LocalDatasetSource(tmp_path / "missing.json")


def test_bundled_dataset_contains_the_planted_test_environment_breaches():
    source = LocalDatasetSource(DEFAULT_DATASET)

    assert [b.name for b in source.lookup("jan.peeters@badsecurityinc.be")] == ["ExampleShop", "FictionalBikeForum"]
    # Pieter Mertens is only in document metadata, so #12 has to derive this address
    assert source.lookup("pieter.mertens@badsecurityinc.be")
    assert source.lookup("emma.claes@badsecurityinc.be") == []


# ---------- Choosing the source through configuration ----------


def test_source_is_chosen_through_settings(monkeypatch, tmp_path):
    config = SimpleNamespace(breach_source="local", breach_dataset=None, hibp_api_key=None, hibp_min_interval_seconds=1.5)
    monkeypatch.setattr("qnsentry.modules.breach.sources._settings", lambda: config)
    assert isinstance(get_breach_source(), LocalDatasetSource)

    config.breach_dataset = write_dataset(tmp_path, {"breaches": {}, "accounts": {}})
    assert get_breach_source().lookup("jan.peeters@badsecurityinc.be") == []

    config.breach_source = "hibp"
    with pytest.raises(RuntimeError, match="HIBP_API_KEY"):
        get_breach_source()

    config.hibp_api_key = "test-key"
    source = get_breach_source()
    assert isinstance(source, HibpSource)
    assert source.min_interval == 1.5

    config.breach_source = "something-else"
    with pytest.raises(ValueError, match="Unknown breach source"):
        get_breach_source()


def test_explicit_source_does_not_need_the_settings(monkeypatch):
    # The CLI passes the source itself, so it works without a database configuration
    def no_settings():
        raise AssertionError("settings should not be loaded")

    monkeypatch.setattr("qnsentry.modules.breach.sources._settings", no_settings)
    assert isinstance(get_breach_source("local"), LocalDatasetSource)


# ---------- Have I Been Pwned source (#13): the HTTP connection is faked ----------

HIBP_SHOP = {"Name": "ExampleShop", "BreachDate": "2021-06-22", "DataClasses": ["Email addresses", "Passwords"]}


class FakeHibp:
    """Stands in for urlopen: answers with the next queued response (a list = 200, an int = error)."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        answer = self.responses.pop(0)
        if isinstance(answer, int):
            headers = {"Retry-After": "3"} if answer == 429 else {}
            raise urllib.error.HTTPError(request.full_url, answer, "error", headers, io.BytesIO())
        return io.BytesIO(json.dumps(answer).encode())


class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.slept = []

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds

    def __call__(self):
        return self.now


def hibp(*responses, **kwargs):
    clock = FakeClock()
    fake = FakeHibp(*responses)
    source = HibpSource("test-key", opener=fake, sleep=clock.sleep, clock=clock, **kwargs)
    return source, fake, clock


def test_hibp_turns_breaches_into_the_shared_shape():
    source, fake, _ = hibp([HIBP_SHOP])

    assert source.lookup(" Jan.Peeters@badsecurityinc.be ") == [
        Breach("ExampleShop", "2021-06-22", ("Email addresses", "Passwords"))
    ]
    request = fake.requests[0]
    assert request.full_url.endswith("/breachedaccount/jan.peeters%40badsecurityinc.be?truncateResponse=false")
    assert request.get_header("Hibp-api-key") == "test-key"
    assert request.get_header("User-agent")


def test_hibp_404_means_no_breaches():
    source, _, _ = hibp(404)
    assert source.lookup("emma.claes@badsecurityinc.be") == []


def test_hibp_waits_between_requests_to_respect_the_rate_limit():
    source, _, clock = hibp(404, 404, min_interval=6.0)

    source.lookup("a@badsecurityinc.be")
    clock.now += 2.0  # the next address comes 2 seconds later
    source.lookup("b@badsecurityinc.be")

    assert clock.slept == [4.0]


def test_hibp_retries_after_429_with_the_retry_after_delay():
    source, fake, clock = hibp(429, [HIBP_SHOP], min_interval=0)

    assert source.lookup("jan.peeters@badsecurityinc.be")[0].name == "ExampleShop"
    assert len(fake.requests) == 2
    assert clock.slept == [3.5]


def test_hibp_gives_up_after_repeated_429():
    source, _, _ = hibp(429, 429, min_interval=0, max_retries=1)
    with pytest.raises(RuntimeError, match="429"):
        source.lookup("jan.peeters@badsecurityinc.be")


def test_hibp_invalid_key_fails_the_module_instead_of_reporting_nothing():
    source, _, _ = hibp(401)
    with pytest.raises(RuntimeError, match="API key is invalid"):
        BreachModule(lambda: source).run(ScanContext(domain="badsecurityinc.be", emails=["jan.peeters@badsecurityinc.be"]))


def test_hibp_findings_credit_the_source():
    source, _, _ = hibp([HIBP_SHOP])
    [finding] = BreachModule(lambda: source).run(ScanContext(domain="", emails=["jan.peeters@badsecurityinc.be"]))
    assert "haveibeenpwned.com" in finding.details["source"]


def test_hibp_needs_an_api_key():
    with pytest.raises(RuntimeError, match="HIBP_API_KEY"):
        HibpSource("")


# ---------- Findings ----------


def test_breach_with_passwords_is_high():
    finding = to_finding("jan.peeters@badsecurityinc.be", [SHOP, FORUM], origin="found publicly")

    assert finding.severity == Severity.HIGH
    assert finding.type == "breached_email"
    assert finding.module == "breach"
    assert finding.title == "jan.peeters@badsecurityinc.be appears in 2 data breaches"
    assert "passwords" in finding.description
    # Newest breach first, and only name, date and kinds of data (GDPR data minimisation)
    assert finding.details["breaches"] == [
        {"name": "ExampleShop", "date": "2021-06-22", "data": ["Email addresses", "Passwords"]},
        {"name": "FictionalBikeForum", "date": "2019-03-10", "data": ["Email addresses", "Usernames"]},
    ]
    assert finding.details["exposed_data"] == ["Email addresses", "Passwords", "Usernames"]


def test_breach_without_passwords_is_medium():
    finding = to_finding("sofie.maes@badsecurityinc.be", [FORUM], origin="found publicly")

    assert finding.severity == Severity.MEDIUM
    assert finding.title == "sofie.maes@badsecurityinc.be appears in 1 data breach"


def test_breach_of_only_the_address_is_low():
    spam_list = Breach("PretendSpamList", "2022-11-30", ("Email addresses",))

    assert to_finding("info@badsecurityinc.be", [spam_list], origin="found publicly").severity == Severity.LOW
    # As soon as a second breach leaked more, the address is medium again
    assert to_finding("info@badsecurityinc.be", [spam_list, FORUM], origin="found publicly").severity == Severity.MEDIUM


# ---------- The module ----------


def test_module_checks_each_address_from_the_context_once():
    source = FakeSource({"jan.peeters@badsecurityinc.be": [SHOP]})
    context = ScanContext(
        domain="badsecurityinc.be",
        emails=["Jan.Peeters@badsecurityinc.be", "jan.peeters@badsecurityinc.be", "emma.claes@badsecurityinc.be", " "],
    )

    findings = BreachModule(lambda: source).run(context)

    assert [f.asset for f in findings] == ["jan.peeters@badsecurityinc.be"]
    assert findings[0].details["origin"] == "found publicly"
    assert source.looked_up == ["emma.claes@badsecurityinc.be", "jan.peeters@badsecurityinc.be"]


def test_module_without_addresses_returns_no_findings():
    assert BreachModule(lambda: FakeSource({})).run(ScanContext(domain="badsecurityinc.be")) == []


def test_breach_module_replaces_the_placeholder_and_can_be_stored():
    from qnsentry.db import models

    assert isinstance(MODULES_BY_NAME["breach"], BreachModule)

    row = models.Finding(**asdict(to_finding("jan.peeters@badsecurityinc.be", [SHOP], "found publicly")))
    assert row.severity == "high"
