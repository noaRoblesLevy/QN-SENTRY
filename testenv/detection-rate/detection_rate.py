"""Measure how many planted findings a scan detects (issue #47).

Compares the findings of a scan with expected-findings.json, the ground truth of the
BadSecurityInc test environment, and reports per module:
- found: expected findings the scan reported (and whether the severity matches)
- missed: expected findings the scan did not report
- unexpected: findings that are not in the ground truth
- false positives: findings that must not appear (e.g. the cleaned document)

Pending entries (a module or part of the test environment that does not exist yet) are
listed but do not count for the detection rate.

Usage (standard library only):
    python testenv/detection-rate/detection_rate.py --api http://localhost:8080 --scan 12
    python testenv/detection-rate/detection_rate.py --findings findings.json --json
"""

import argparse
import json
import sys
import urllib.request
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

EXPECTED_FILE = Path(__file__).resolve().parent / "expected-findings.json"
IGNORED_TYPES = {"placeholder"}  # stand-ins for modules that are not built yet
MODULES = ["attack_surface", "metadata", "phishing", "breach"]


@dataclass
class ModuleResult:
    found: list[dict] = field(default_factory=list)
    missed: list[dict] = field(default_factory=list)
    pending: list[dict] = field(default_factory=list)
    severity_differs: list[dict] = field(default_factory=list)
    unexpected: list[dict] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)

    @property
    def expected_count(self) -> int:
        return len(self.found) + len(self.missed)


def matches(rule: dict, finding: dict) -> bool:
    """A finding matches a rule on module, type, asset (with * wildcards) and a details subset."""
    if finding.get("module") != rule["module"] or finding.get("type") != rule["type"]:
        return False
    if not fnmatch(str(finding.get("asset", "")).lower(), rule["asset"].lower()):
        return False
    details = finding.get("details") or {}
    return all(details.get(key) == value for key, value in rule.get("details", {}).items())


def evaluate(expected: dict, findings: list[dict]) -> dict[str, ModuleResult]:
    results = {module: ModuleResult() for module in MODULES}
    matched_findings: set[int] = set()

    for rule in expected["expected"]:
        result = results.setdefault(rule["module"], ModuleResult())
        hits = [i for i, f in enumerate(findings) if matches(rule, f)]
        matched_findings.update(hits)
        if rule.get("pending"):
            result.pending.append({**rule, "found_anyway": bool(hits)})
        elif hits:
            severities = sorted({findings[i]["severity"] for i in hits})
            result.found.append(rule)
            if severities != [rule["severity"]]:
                result.severity_differs.append({**rule, "actual": severities})
        else:
            result.missed.append(rule)

    for rule in expected.get("must_not_find", []):
        hits = [i for i, f in enumerate(findings) if matches(rule, f)]
        matched_findings.update(hits)
        if hits:
            results.setdefault(rule["module"], ModuleResult()).false_positives.append(rule)

    for i, finding in enumerate(findings):
        if i not in matched_findings and finding.get("type") not in IGNORED_TYPES:
            results.setdefault(finding.get("module", "?"), ModuleResult()).unexpected.append(finding)
    return results


def rate(found: int, expected: int) -> str:
    return f"{found}/{expected} ({100 * found / expected:.0f}%)" if expected else "-"


def summary(results: dict[str, ModuleResult]) -> dict:
    found = sum(len(r.found) for r in results.values())
    expected = sum(r.expected_count for r in results.values())
    return {
        "detection_rate": round(found / expected, 3) if expected else None,
        "found": found,
        "expected": expected,
        "pending": sum(len(r.pending) for r in results.values()),
        "severity_differs": sum(len(r.severity_differs) for r in results.values()),
        "unexpected": sum(len(r.unexpected) for r in results.values()),
        "false_positives": sum(len(r.false_positives) for r in results.values()),
        "modules": {
            module: {
                "found": [r_["id"] for r_ in r.found],
                "missed": [r_["id"] for r_ in r.missed],
                "pending": [{"id": p["id"], "reason": p["pending"], "found_anyway": p["found_anyway"]} for p in r.pending],
                "severity_differs": [{"id": s["id"], "expected": s["severity"], "actual": s["actual"]} for s in r.severity_differs],
                "unexpected": [f"{f.get('type')}: {f.get('title', f.get('asset'))}" for f in r.unexpected],
                "false_positives": [f["id"] for f in r.false_positives],
            }
            for module, r in results.items()
        },
    }


def print_report(results: dict[str, ModuleResult]) -> None:
    total = summary(results)
    print(f"{'Module':<16} {'Detected':<14} {'Pending':>7} {'Severity differs':>17} {'Unexpected':>11} {'False pos.':>11}")
    for module, r in results.items():
        print(
            f"{module:<16} {rate(len(r.found), r.expected_count):<14} {len(r.pending):>7} "
            f"{len(r.severity_differs):>17} {len(r.unexpected):>11} {len(r.false_positives):>11}"
        )
    print(f"\nDetection rate: {rate(total['found'], total['expected'])}  (pending, not counted: {total['pending']})")

    for module, r in results.items():
        for rule in r.missed:
            print(f"  MISSED     {module}: {rule['id']} ({rule['planted']})")
        for rule in r.severity_differs:
            print(f"  SEVERITY   {module}: {rule['id']} expected {rule['severity']}, got {', '.join(rule['actual'])}")
        for finding in r.unexpected:
            print(f"  UNEXPECTED {module}: {finding.get('type')}: {finding.get('title', finding.get('asset'))}")
        for rule in r.false_positives:
            print(f"  FALSE POS. {module}: {rule['id']} ({rule['reason']})")
        for pending in r.pending:
            note = " (found anyway)" if pending["found_anyway"] else ""
            print(f"  PENDING    {module}: {pending['id']}: {pending['pending']}{note}")


def load_findings(args) -> list[dict]:
    if args.findings:
        return json.loads(Path(args.findings).read_text(encoding="utf-8"))
    url = f"{args.api.rstrip('/')}/api/scans/{args.scan}/findings"
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detection rate of a scan against the planted findings (#47).")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--findings", help="JSON file with the findings of a scan")
    source.add_argument("--api", help="QN-Sentry address, e.g. http://localhost:8080 (needs --scan)")
    parser.add_argument("--scan", type=int, help="scan id when using --api")
    parser.add_argument("--expected", default=str(EXPECTED_FILE), help="ground truth file")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    if args.api and args.scan is None:
        parser.error("--api needs --scan")

    expected = json.loads(Path(args.expected).read_text(encoding="utf-8"))
    results = evaluate(expected, load_findings(args))
    if args.json:
        print(json.dumps(summary(results), indent=2))
    else:
        print_report(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
