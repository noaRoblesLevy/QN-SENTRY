"""Tests for the detection-rate script (#47). Run: pytest testenv/detection-rate"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from detection_rate import EXPECTED_FILE, evaluate, matches, summary  # noqa: E402

EXPECTED = {
    "expected": [
        {"id": "doc", "module": "metadata", "type": "document_metadata", "asset": "https://*example.be/files/a.pdf", "severity": "medium", "planted": "path"},
        {"id": "spf", "module": "phishing", "type": "email_security", "asset": "example.be", "details": {"check": "spf"}, "severity": "high", "planted": "+all"},
        {"id": "dmarc", "module": "phishing", "type": "email_security", "asset": "example.be", "details": {"check": "dmarc"}, "severity": "high", "planted": "p=none"},
        {"id": "later", "module": "breach", "type": "breached_email", "asset": "jan@example.be", "severity": "high", "planted": "x", "pending": "#8"},
    ],
    "must_not_find": [
        {"id": "clean", "module": "metadata", "type": "document_metadata", "asset": "https://*example.be/files/clean.pdf", "reason": "cleaned"},
    ],
}


def finding(module, type_, asset, severity, **details):
    return {"module": module, "type": type_, "asset": asset, "severity": severity, "title": asset, "details": details}


def test_asset_wildcard_and_details_subset():
    rule = EXPECTED["expected"][1]

    assert matches(rule, finding("phishing", "email_security", "example.be", "high", check="spf", record="v=spf1 +all"))
    assert not matches(rule, finding("phishing", "email_security", "example.be", "high", check="dmarc"))
    assert matches(EXPECTED["expected"][0], finding("metadata", "document_metadata", "https://www.example.be/files/a.pdf", "medium"))


def test_found_missed_pending_and_severity():
    findings = [
        finding("metadata", "document_metadata", "https://example.be/files/a.pdf", "low"),  # severity differs
        finding("phishing", "email_security", "example.be", "high", check="spf"),
        finding("attack_surface", "placeholder", "example.be", "info"),  # ignored
    ]

    total = summary(evaluate(EXPECTED, findings))

    assert (total["found"], total["expected"], total["pending"]) == (2, 3, 1)
    assert total["modules"]["phishing"]["missed"] == ["dmarc"]
    assert total["modules"]["metadata"]["severity_differs"] == [{"id": "doc", "expected": "medium", "actual": ["low"]}]
    assert total["unexpected"] == 0


def test_unexpected_findings_and_false_positives():
    findings = [
        finding("metadata", "document_metadata", "https://example.be/files/clean.pdf", "low"),
        finding("phishing", "lookalike_domain", "exampie.be", "high"),
    ]

    total = summary(evaluate(EXPECTED, findings))

    assert total["modules"]["metadata"]["false_positives"] == ["clean"]
    assert total["modules"]["phishing"]["unexpected"] == ["lookalike_domain: exampie.be"]


def test_pending_entry_found_anyway_is_reported_but_not_counted():
    total = summary(evaluate(EXPECTED, [finding("breach", "breached_email", "jan@example.be", "high")]))

    assert total["expected"] == 3
    assert total["modules"]["breach"]["pending"][0]["found_anyway"] is True


def test_ground_truth_file_is_valid():
    data = json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))
    ids = [rule["id"] for rule in data["expected"] + data["must_not_find"]]

    assert len(ids) == len(set(ids)), "ids must be unique"
    for rule in data["expected"]:
        assert rule["severity"] in {"info", "low", "medium", "high", "critical"}
        assert {"module", "type", "asset", "planted"} <= set(rule)
