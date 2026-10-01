"""Tests for the email security check (#29). DNS answers are faked, so no network is needed."""

import dns.exception
import dns.resolver
import pytest

from qnsentry.db.models import Severity
from qnsentry.modules.phishing import email_security
from qnsentry.modules.phishing.email_security import (
    SPF_LOOKUP_LIMIT,
    LookupFailed,
    check_email_security,
    count_spf_lookups,
    evaluate_dkim,
    evaluate_dmarc,
    evaluate_spf,
    evaluate_spf_lookups,
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


# ---------- SPF lookup limit (#44) ----------


def txt_from(answers: dict[str, list[str]]):
    """get_txt for count_spf_lookups: answers per name, [] for names that do not exist."""
    asked = []

    def get_txt(name):
        asked.append(name)
        return answers.get(name, [])

    get_txt.asked = asked
    return get_txt


def test_terms_that_need_no_lookup_are_not_counted():
    record = "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"
    assert count_spf_lookups(DOMAIN, record, txt_from({})).count == 0


def test_lookups_are_counted_through_included_records():
    answers = {
        "spf.protection.outlook.com": ["v=spf1 include:spf-a.outlook.com include:spf-b.outlook.com -all"],
        "spf-a.outlook.com": ["v=spf1 ip4:192.0.2.0/24 -all"],
        "spf-b.outlook.com": ["v=spf1 a mx -all"],
        "_spf.newsletter.example": ["v=spf1 exists:%{i}.check.example -all"],
    }
    record = "v=spf1 a mx:mail.badsecurityinc.be include:spf.protection.outlook.com ~include:_spf.newsletter.example -all"

    lookups = count_spf_lookups(DOMAIN, record, txt_from(answers))

    # a, mx, include, include (own record) + 2 includes + a, mx + exists (included records)
    assert lookups.count == 9
    assert lookups.followed == [DOMAIN, "spf.protection.outlook.com", "spf-a.outlook.com", "spf-b.outlook.com", "_spf.newsletter.example"]
    assert evaluate_spf_lookups(DOMAIN, lookups) == []


def test_more_than_ten_lookups_makes_spf_ignored():
    # Several mail services, each costing a few lookups
    answers = {f"_spf.service{i}.example": ["v=spf1 a mx include:_spf.shared.example -all"] for i in range(4)}
    answers["_spf.shared.example"] = ["v=spf1 ip4:198.51.100.0/24 -all"]
    record = "v=spf1 " + " ".join(f"include:_spf.service{i}.example" for i in range(4)) + " -all"

    lookups = count_spf_lookups(DOMAIN, record, txt_from(answers))
    [finding] = evaluate_spf_lookups(DOMAIN, lookups)

    assert lookups.count > SPF_LOOKUP_LIMIT
    assert finding.severity == Severity.MEDIUM
    assert finding.details["check"] == "spf_permerror"
    assert finding.details["reason"] == "too_many_lookups"
    assert "ignored" in finding.title and "even when it ends in '-all'" in finding.description


def test_counting_stops_after_the_limit():
    # A record with a thousand includes must not cause a thousand lookups
    names = [f"s{i}.example" for i in range(1000)]
    record = "v=spf1 " + " ".join(f"include:{name}" for name in names) + " -all"
    get_txt = txt_from({name: ["v=spf1 ip4:192.0.2.1 -all"] for name in names})

    lookups = count_spf_lookups(DOMAIN, record, get_txt)

    assert lookups.count == SPF_LOOKUP_LIMIT + 1
    assert len(get_txt.asked) == SPF_LOOKUP_LIMIT


def test_loop_between_included_records_does_not_hang():
    answers = {
        "_spf.a.example": ["v=spf1 include:_spf.b.example -all"],
        "_spf.b.example": ["v=spf1 include:_spf.a.example -all"],
    }

    lookups = count_spf_lookups(DOMAIN, "v=spf1 include:_spf.a.example -all", txt_from(answers))
    [finding] = evaluate_spf_lookups(DOMAIN, lookups)

    assert lookups.loop == "_spf.a.example"
    assert "loop" in finding.title


def test_redirect_is_followed_but_ignored_when_the_record_has_all():
    answers = {"_spf.parent.example": ["v=spf1 a mx -all"]}

    assert count_spf_lookups(DOMAIN, "v=spf1 redirect=_spf.parent.example", txt_from(answers)).count == 3
    assert count_spf_lookups(DOMAIN, "v=spf1 -all redirect=_spf.parent.example", txt_from(answers)).count == 0


def test_too_many_lookups_is_reported_by_the_full_check(monkeypatch):
    includes = {f"_spf{i}.example": ["v=spf1 a mx ptr -all"] for i in range(4)}
    record = "v=spf1 " + " ".join(f"include:{name}" for name in includes) + " -all"
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_dns({DOMAIN: [record], f"_dmarc.{DOMAIN}": ["v=DMARC1; p=reject"], **includes}),
    )

    checks = [f.details["check"] for f in check_email_security(DOMAIN, nameservers=["192.0.2.53"])]

    assert checks == ["spf_permerror", "dkim"]


def test_failing_include_lookup_skips_only_the_count(monkeypatch):
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_dns({DOMAIN: ["v=spf1 include:_spf.down.example ~all"]}, failing={"_spf.down.example"}),
    )

    checks = [f.details["check"] for f in check_email_security(DOMAIN, nameservers=["192.0.2.53"])]

    assert checks == ["spf", "dmarc", "dkim"]


@pytest.mark.parametrize(
    ("record", "answers", "broken", "problem"),
    [
        # A mail service that was stopped removed its record, but the include stayed
        ("v=spf1 include:_spf.removed-service.example -all", {}, "include:_spf.removed-service.example", "has no SPF record"),
        ("v=spf1 include:_spf.double.example -all",
         {"_spf.double.example": ["v=spf1 a -all", "v=spf1 mx -all"]}, "include:_spf.double.example", "has 2 SPF records"),
        ("v=spf1 redirect=_spf.gone.example", {"_spf.gone.example": ["some other TXT record"]}, "redirect=_spf.gone.example", "has no SPF record"),
    ],
    ids=["missing include", "two records", "redirect without SPF"],
)
def test_include_without_exactly_one_spf_record_makes_spf_ignored(record, answers, broken, problem):
    # RFC 7208 5.2 and 6.1: a permerror, so receivers ignore the whole record, like over the limit
    lookups = count_spf_lookups(DOMAIN, record, txt_from(answers))
    [finding] = evaluate_spf_lookups(DOMAIN, lookups)

    assert lookups.broken == (broken, problem)
    assert finding.details["reason"] == "broken_include"
    assert finding.details["broken"] == broken
    assert finding.title == f"SPF record on {DOMAIN} is ignored: {broken} {problem}"


def test_ignored_spf_makes_a_weak_dmarc_high(monkeypatch):
    # An SPF permerror protects as little as no SPF: with no DMARC nothing stops spoofing
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_dns({DOMAIN: ["v=spf1 include:_spf.removed-service.example -all"]}),
    )

    findings = {f.details["check"]: f for f in check_email_security(DOMAIN, nameservers=["192.0.2.53"])}

    assert findings["spf_permerror"].severity == Severity.MEDIUM
    assert findings["dmarc"].severity == Severity.HIGH
    assert "nothing on this domain does" in findings["dmarc"].description


def test_valid_spf_keeps_dmarc_medium(monkeypatch):
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_dns({DOMAIN: ["v=spf1 ip4:192.0.2.1 -all"]}))

    findings = {f.details["check"]: f for f in check_email_security(DOMAIN, nameservers=["192.0.2.53"])}

    assert "spf_permerror" not in findings
    assert findings["dmarc"].severity == Severity.MEDIUM


def test_lookup_failure_propagates_from_the_counter():
    def failing(name):
        raise LookupFailed(name)

    with pytest.raises(LookupFailed):
        count_spf_lookups(DOMAIN, "v=spf1 include:_spf.x.example -all", failing)


def test_dkim_selectors_include_the_common_ones():
    assert {"default", "google", "selector1", "selector2"} <= set(email_security.DKIM_SELECTORS)
