"""Tests for the detection-rate script (#47). Run: pytest testenv/detection-rate"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from detection_rate import EXPECTED_FILE, assign, evaluate, main, matches, summary  # noqa: E402

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
    assert total["modules"]["metadata"]["severity_differs"] == [{"id": "doc", "expected": "medium", "actual": "low"}]
    assert total["unexpected"] == 0
    assert total["detection_rate"] == round(2 / 3, 3)
    assert total["detected_with_expected_severity"] == round(1 / 3, 3)


def test_one_finding_never_ticks_off_two_entries():
    # Two entries with the same pattern (like the admin login and the outdated server on dev.)
    rules = [
        {"id": "a", "module": "attack_surface", "type": "web_service", "asset": "*dev.example.be*", "severity": "medium", "planted": "x"},
        {"id": "b", "module": "attack_surface", "type": "web_service", "asset": "*dev.example.be*", "severity": "medium", "planted": "y"},
    ]
    one = [finding("attack_surface", "web_service", "https://dev.example.be", "medium")]

    total = summary(evaluate({"expected": rules}, one))

    assert (total["found"], total["expected"]) == (1, 2)


def test_assignment_finds_the_pairing_a_greedy_match_would_miss():
    # Rule 0 matches both findings, rule 1 only the first. "First match wins" would give
    # finding 0 to rule 0 and leave rule 1 missed; the matching pairs 0-1 and 1-0.
    rules = [
        {"id": "any", "module": "m", "type": "t", "asset": "*.example.be", "severity": "low", "planted": "x"},
        {"id": "www", "module": "m", "type": "t", "asset": "www.example.be", "severity": "low", "planted": "y"},
    ]
    findings = [finding("m", "t", "www.example.be", "low"), finding("m", "t", "dev.example.be", "low")]

    assert assign(rules, findings) == {0: 1, 1: 0}


def test_precision_counts_unexpected_duplicate_and_false_positive_findings():
    findings = [
        finding("phishing", "email_security", "example.be", "high", check="spf"),
        finding("phishing", "email_security", "example.be", "high", check="spf"),  # duplicate
        finding("phishing", "lookalike_domain", "exampie.be", "high"),  # unexpected
        finding("metadata", "document_metadata", "https://example.be/files/clean.pdf", "low"),  # false positive
    ]

    total = summary(evaluate(EXPECTED, findings))

    assert (total["found"], total["duplicates"], total["unexpected"], total["false_positives"]) == (1, 1, 1, 1)
    assert total["precision"] == 0.25
    assert total["modules"]["phishing"]["unexpected"] == ["lookalike_domain: exampie.be"]
    assert total["modules"]["metadata"]["false_positives"] == ["clean"]


def test_reporting_everything_does_not_give_a_perfect_score():
    planted = [
        finding("metadata", "document_metadata", "https://example.be/files/a.pdf", "medium"),
        finding("phishing", "email_security", "example.be", "high", check="spf"),
        finding("phishing", "email_security", "example.be", "high", check="dmarc"),
    ]
    noise = [finding("phishing", "lookalike_domain", f"example{i}.be", "low") for i in range(50)]

    total = summary(evaluate(EXPECTED, planted + noise))

    assert total["detection_rate"] == 1.0
    assert total["precision"] == round(3 / 53, 3)


def test_pending_entry_found_anyway_is_reported_but_not_counted():
    total = summary(evaluate(EXPECTED, [finding("breach", "breached_email", "jan@example.be", "high")]))

    assert total["expected"] == 3
    assert total["unexpected"] == 0
    assert total["modules"]["breach"]["pending"][0]["found_anyway"] is True


def test_json_output_records_when_and_against_which_commit(tmp_path, capsys):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([finding("phishing", "email_security", "example.be", "high", check="spf")]))
    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps(EXPECTED))

    main(["--findings", str(findings), "--expected", str(expected), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert {"source", "measured_at", "commit", "detection_rate", "precision"} <= set(output)


def test_ground_truth_file_is_valid():
    data = json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))
    ids = [rule["id"] for rule in data["expected"] + data["must_not_find"]]

    assert len(ids) == len(set(ids)), "ids must be unique"
    for rule in data["expected"]:
        assert rule["severity"] in {"info", "low", "medium", "high", "critical"}
        assert {"module", "type", "asset", "planted"} <= set(rule)


def test_website_readme_agrees_with_the_ground_truth():
    # The website README keeps an "Expected severity" column for readers; the JSON is the
    # single source, so the README may never say something else
    readme = (Path(__file__).resolve().parents[1] / "website" / "README.md").read_text(encoding="utf-8")
    data = json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))
    expected = {rule["asset"].rsplit("/", 1)[-1]: rule["severity"] for rule in data["expected"] if rule["type"] == "document_metadata"}
    forbidden = {rule["asset"].rsplit("/", 1)[-1] for rule in data["must_not_find"] if rule["type"] == "document_metadata"}

    rows = {}
    for line in readme.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[0].startswith("`") and "." in cells[0]:
            rows[cells[0].split("`")[1]] = cells[2].split(" ")[0]

    assert {name: severity for name, severity in rows.items() if name not in forbidden} == expected
    assert all(rows[name] == "no" for name in forbidden)
