"""Tests for the Breach module and its local dataset source (#11). No network needed."""

import json
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
    config = SimpleNamespace(breach_source="local", breach_dataset=None)
    monkeypatch.setattr("qnsentry.modules.breach.sources._settings", lambda: config)
    assert isinstance(get_breach_source(), LocalDatasetSource)

    config.breach_dataset = write_dataset(tmp_path, {"breaches": {}, "accounts": {}})
    assert get_breach_source().lookup("jan.peeters@badsecurityinc.be") == []

    config.breach_source = "hibp"
    with pytest.raises(RuntimeError, match="#13"):
        get_breach_source()

    config.breach_source = "something-else"
    with pytest.raises(ValueError, match="Unknown breach source"):
        get_breach_source()


def test_explicit_source_does_not_need_the_settings(monkeypatch):
    # The CLI passes the source itself, so it works without a database configuration
    def no_settings():
        raise AssertionError("settings should not be loaded")

    monkeypatch.setattr("qnsentry.modules.breach.sources._settings", no_settings)
    assert isinstance(get_breach_source("local"), LocalDatasetSource)


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
