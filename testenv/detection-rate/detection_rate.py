"""Measure how many planted findings a scan detects (issue #47).

Compares the findings of a scan with expected-findings.json, the ground truth of the
BadSecurityInc test environment, and reports per module:
- found: expected entries the scan reported, and whether the severity matches
- missed: expected entries the scan did not report
- unexpected: findings that match no entry of the ground truth
- duplicates: extra findings for an entry that was already found
- false positives: findings that must not appear (e.g. the cleaned document)

Each finding counts for at most one entry, and each entry for at most one finding, so
one finding can never tick off two entries. Pending entries (a module or part of the
test environment that does not exist yet) are listed but do not count.

Three numbers summarise the result:
- detection rate (recall): found / expected
- detected with the expected severity: found with the right severity / expected
- precision: found / (found + unexpected + duplicates + false positives), so a scanner
  that reports everything cannot score well

Usage (standard library only):
    python testenv/detection-rate/detection_rate.py --api http://localhost:8000 --scan 12
    python testenv/detection-rate/detection_rate.py --findings findings.json --json
"""

import argparse
import json
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
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
    duplicates: list[dict] = field(default_factory=list)
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


def assign(rules: list[dict], findings: list[dict]) -> dict[int, int]:
    """Pair rules with findings, each used at most once, with as many pairs as possible.

    A greedy "first match wins" could give a finding to the wrong rule and leave another
    rule missed although a pairing for both exists. This is a maximum bipartite matching
    (augmenting paths), which is small enough here: tens of rules and findings.
    Returns {rule index: finding index}.
    """
    candidates = [[i for i, finding in enumerate(findings) if matches(rule, finding)] for rule in rules]
    owner: dict[int, int] = {}  # finding index -> rule index

    def try_rule(rule: int, seen: set[int]) -> bool:
        for finding in candidates[rule]:
            if finding in seen:
                continue
            seen.add(finding)
            if finding not in owner or try_rule(owner[finding], seen):
                owner[finding] = rule
                return True
        return False

    for rule in range(len(rules)):
        try_rule(rule, set())
    return {rule: finding for finding, rule in owner.items()}


def evaluate(expected: dict, findings: list[dict]) -> dict[str, ModuleResult]:
    results = {module: ModuleResult() for module in MODULES}
    findings = [f for f in findings if f.get("type") not in IGNORED_TYPES]
    rules = expected["expected"]
    pairs = assign(rules, findings)
    used = set(pairs.values())

    for index, rule in enumerate(rules):
        result = results.setdefault(rule["module"], ModuleResult())
        finding = findings[pairs[index]] if index in pairs else None
        if rule.get("pending"):
            result.pending.append({**rule, "found_anyway": finding is not None})
        elif finding is not None:
            result.found.append(rule)
            if finding["severity"] != rule["severity"]:
                result.severity_differs.append({**rule, "actual": finding["severity"]})
        else:
            result.missed.append(rule)

    for i, finding in enumerate(findings):
        if i in used:
            continue
        module = results.setdefault(finding.get("module", "?"), ModuleResult())
        forbidden = next((rule for rule in expected.get("must_not_find", []) if matches(rule, finding)), None)
        if forbidden:
            module.false_positives.append(forbidden)
        elif any(matches(rule, finding) for rule in rules):
            module.duplicates.append(finding)  # a second finding for an entry already found
        else:
            module.unexpected.append(finding)
    return results


def ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 3) if denominator else None


def summary(results: dict[str, ModuleResult], meta: dict | None = None) -> dict:
    def total(attribute: str) -> int:
        return sum(len(getattr(r, attribute)) for r in results.values())

    found = total("found")
    expected = sum(r.expected_count for r in results.values())
    right_severity = found - total("severity_differs")
    reported = found + total("unexpected") + total("duplicates") + total("false_positives")
    return {
        **(meta or {}),
        "detection_rate": ratio(found, expected),
        "detected_with_expected_severity": ratio(right_severity, expected),
        "precision": ratio(found, reported),
        "found": found,
        "expected": expected,
        "pending": total("pending"),
        "severity_differs": total("severity_differs"),
        "unexpected": total("unexpected"),
        "duplicates": total("duplicates"),
        "false_positives": total("false_positives"),
        "modules": {
            module: {
                "found": [rule["id"] for rule in r.found],
                "missed": [rule["id"] for rule in r.missed],
                "pending": [{"id": p["id"], "reason": p["pending"], "found_anyway": p["found_anyway"]} for p in r.pending],
                "severity_differs": [{"id": s["id"], "expected": s["severity"], "actual": s["actual"]} for s in r.severity_differs],
                "unexpected": [describe(f) for f in r.unexpected],
                "duplicates": [describe(f) for f in r.duplicates],
                "false_positives": [rule["id"] for rule in r.false_positives],
            }
            for module, r in results.items()
        },
    }


def describe(finding: dict) -> str:
    return f"{finding.get('type')}: {finding.get('title', finding.get('asset'))}"


def percent(value: float | None) -> str:
    return f"{100 * value:.0f}%" if value is not None else "-"


def fraction(found: int, expected: int) -> str:
    return f"{found}/{expected} ({100 * found / expected:.0f}%)" if expected else "-"


def print_report(results: dict[str, ModuleResult], meta: dict) -> None:
    total = summary(results, meta)
    print(f"Scan {meta['source']}, measured {meta['measured_at']}, ground truth at commit {meta['commit']}\n")
    print(f"{'Module':<16} {'Detected':<14} {'Pending':>7} {'Sev. differs':>12} {'Unexpected':>10} {'Duplicates':>10} {'False pos.':>10}")
    for module, r in results.items():
        print(
            f"{module:<16} {fraction(len(r.found), r.expected_count):<14} {len(r.pending):>7} "
            f"{len(r.severity_differs):>12} {len(r.unexpected):>10} {len(r.duplicates):>10} {len(r.false_positives):>10}"
        )
    print(
        f"\nDetection rate (recall): {fraction(total['found'], total['expected'])}"
        f"\nDetected with the expected severity: {percent(total['detected_with_expected_severity'])}"
        f"\nPrecision: {percent(total['precision'])}"
        f"\nPending, not counted: {total['pending']}"
    )

    for module, r in results.items():
        for rule in r.missed:
            print(f"  MISSED     {module}: {rule['id']} ({rule['planted']})")
        for rule in r.severity_differs:
            print(f"  SEVERITY   {module}: {rule['id']} expected {rule['severity']}, got {rule['actual']}")
        for finding in r.unexpected:
            print(f"  UNEXPECTED {module}: {describe(finding)}")
        for finding in r.duplicates:
            print(f"  DUPLICATE  {module}: {describe(finding)}")
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


def git_commit(expected_file: Path) -> str:
    """The commit of the ground truth, so every result says which version it used.

    "-dirty" is added when the ground truth file has uncommitted changes: the commit alone
    would then not describe what was measured.
    """
    folder = expected_file.resolve().parent
    try:
        head = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=10, cwd=folder
        )
        changed = subprocess.run(
            ["git", "status", "--porcelain", "--", expected_file.name], capture_output=True, text=True, timeout=10, cwd=folder
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    commit = head.stdout.strip()
    if not commit:
        return "unknown"
    return f"{commit}-dirty" if changed.stdout.strip() else commit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detection rate of a scan against the planted findings (#47).")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--findings", help="JSON file with the findings of a scan")
    source.add_argument("--api", help="QN-Sentry API address, e.g. http://localhost:8000 (needs --scan)")
    parser.add_argument("--scan", type=int, help="scan id when using --api")
    parser.add_argument("--expected", default=str(EXPECTED_FILE), help="ground truth file")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    if args.api and args.scan is None:
        parser.error("--api needs --scan")

    expected = json.loads(Path(args.expected).read_text(encoding="utf-8"))
    results = evaluate(expected, load_findings(args))
    meta = {
        "source": f"{args.api} scan {args.scan}" if args.api else args.findings,
        "measured_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "commit": git_commit(Path(args.expected)),
    }
    if args.json:
        print(json.dumps(summary(results, meta), indent=2))
    else:
        print_report(results, meta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
