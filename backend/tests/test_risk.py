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
        (["medium"], 8, "low"),
        (["high"], 18, "low"),
        (["high", "high"], 33, "moderate"),
        (["critical"], 39, "moderate"),
        # The test environment on 30/09: 6 high, 2 medium, 1 low
        (["high"] * 6 + ["medium"] * 2 + ["low"], 75, "very_high"),
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
    assert scan(ScanStatus.COMPLETED, Severity.HIGH).risk_score == 18
    assert scan(ScanStatus.PARTIAL, Severity.HIGH, Severity.HIGH).risk_level == "moderate"


def test_client_risk_is_the_riskiest_domain_using_its_latest_scored_scan():
    shop = models.Domain(
        name="shop.example",
        # Newest first: the running scan has no score, so the completed one below it counts
        scans=[scan(ScanStatus.RUNNING, scan_id=3), scan(ScanStatus.COMPLETED, Severity.CRITICAL, scan_id=2)],
    )
    site = models.Domain(name="site.example", scans=[scan(ScanStatus.COMPLETED, Severity.LOW, scan_id=1)])
    client = models.Client(name="Example", domains=[site, shop])

    assert client.risk_score == 39
    assert client.risk_level == "moderate"


def test_client_without_scored_scans_has_no_risk():
    client = models.Client(name="New", domains=[models.Domain(name="new.example", scans=[])])

    assert client.risk_score is None
