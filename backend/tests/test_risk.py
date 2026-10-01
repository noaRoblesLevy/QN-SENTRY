"""Tests for the risk score (#19). No database: models are built in memory."""

import pytest

from qnsentry.db import models
from qnsentry.db.models import ScanStatus, Severity
from qnsentry.risk import compute_risk, level_of


def test_empty_or_only_informational_findings_score_zero():
    assert compute_risk([]).score == 0
    assert compute_risk(["info"] * 20).score == 0
    assert compute_risk([]).level == "low"


@pytest.mark.parametrize(
    ("severities", "score", "level"),
    [
        (["low"], 2, "low"),
        # One finding: the floor of its severity, so the level matches the severity
        (["medium"], 25, "moderate"),
        (["high"], 50, "high"),
        (["critical"], 75, "very_high"),
        (["high", "high"], 50, "high"),
        # Many low findings still add up through the curve
        (["low"] * 20, 33, "moderate"),
        # Real scan of 30/09: metadata 4 medium + 7 low, phishing 4 high + 1 low
        (["medium"] * 4 + ["low"] * 8 + ["high"] * 4, 72, "high"),
        # Full ground truth of the test environment (#47): 7 high, 6 medium, 9 low
        (["high"] * 7 + ["medium"] * 6 + ["low"] * 9, 87, "very_high"),
    ],
)
def test_documented_examples(severities, score, level):
    risk = compute_risk(severities)

    assert (risk.score, risk.level) == (score, level)


def test_adding_a_finding_never_lowers_the_score():
    severities: list[str] = []
    previous = 0
    for severity in ["info", "low", "medium", "high", "critical"] * 4:
        severities.append(severity)
        score = compute_risk(severities).score
        assert previous <= score <= 100
        previous = score


def test_floor_only_applies_to_the_worst_finding():
    # Above the floor the curve decides, so more findings still weigh more than one
    assert compute_risk(["high"] * 10).score > compute_risk(["high"]).score
    assert compute_risk(["medium", "info", "info"]).score == 25
    assert compute_risk(["info"]).score == 0


def test_accepts_severity_enums_from_the_database():
    assert compute_risk([Severity.HIGH, Severity.HIGH]).score == compute_risk(["high", "high"]).score


@pytest.mark.parametrize(("score", "level"), [(0, "low"), (24, "low"), (25, "moderate"), (50, "high"), (75, "very_high"), (100, "very_high")])
def test_level_boundaries(score, level):
    assert level_of(score) == level


# ---------- Scans and clients ----------


def scan(status, *severities, scan_id=1):
    return models.Scan(id=scan_id, status=status, findings=[models.Finding(severity=s) for s in severities])


@pytest.mark.parametrize("status", [ScanStatus.QUEUED, ScanStatus.RUNNING, ScanStatus.FAILED])
def test_unfinished_or_failed_scan_has_no_score(status):
    assert scan(status, Severity.HIGH).risk_score is None


def test_finished_and_partial_scans_have_a_score():
    assert scan(ScanStatus.COMPLETED, Severity.HIGH).risk_score == 50
    assert scan(ScanStatus.PARTIAL, Severity.HIGH, Severity.HIGH).risk_level == "high"


def test_partial_scan_keeps_its_score_but_is_flagged_incomplete():
    assert scan(ScanStatus.COMPLETED, Severity.HIGH).risk_complete is True
    assert scan(ScanStatus.PARTIAL, Severity.HIGH).risk_complete is False
    assert scan(ScanStatus.RUNNING, Severity.HIGH).risk_complete is None


def test_client_risk_is_the_riskiest_domain_using_its_latest_scored_scan():
    shop = models.Domain(
        name="shop.example",
        # Newest first: the running scan has no score, so the completed one below it counts
        scans=[scan(ScanStatus.RUNNING, scan_id=3), scan(ScanStatus.COMPLETED, Severity.CRITICAL, scan_id=2)],
    )
    site = models.Domain(name="site.example", scans=[scan(ScanStatus.COMPLETED, Severity.LOW, scan_id=1)])
    client = models.Client(name="Example", domains=[site, shop])

    assert client.risk_score == 75
    assert client.risk_level == "very_high"


def test_client_risk_carries_the_completeness_of_the_scan_it_comes_from():
    shop = models.Domain(name="shop.example", scans=[scan(ScanStatus.PARTIAL, Severity.HIGH, scan_id=2)])
    site = models.Domain(name="site.example", scans=[scan(ScanStatus.COMPLETED, Severity.LOW, scan_id=1)])

    assert models.Client(name="Example", domains=[site, shop]).risk_complete is False


def test_client_without_scored_scans_has_no_risk():
    client = models.Client(name="New", domains=[models.Domain(name="new.example", scans=[])])

    assert client.risk_score is None
