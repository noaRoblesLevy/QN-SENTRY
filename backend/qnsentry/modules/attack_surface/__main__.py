"""Command-line tool for the attack surface module (subfinder and dnsx must be installed,
e.g. in the worker):

    python -m qnsentry.modules.attack_surface badsecurityinc.be
    python -m qnsentry.modules.attack_surface badsecurityinc.be --json

Only scan domains you own or have written permission to assess.
"""

import argparse
import json
import sys
import time
from dataclasses import asdict

from qnsentry.modules.attack_surface import AttackSurfaceModule
from qnsentry.modules.base import ScanContext


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m qnsentry.modules.attack_surface",
        description="Find the subdomains of a domain in passive sources and resolve them (issue #4).",
    )
    parser.add_argument("domain", help="the client's domain, e.g. badsecurityinc.be")
    parser.add_argument("--json", action="store_true", help="print the findings in the data contract format")
    args = parser.parse_args(argv)

    print(f"Searching passive sources for subdomains of {args.domain} ...", file=sys.stderr)
    context = ScanContext(domain=args.domain.lower().rstrip("."))
    started = time.monotonic()
    try:
        findings = AttackSurfaceModule().run(context)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started
    for warning in context.warnings:
        print(f"Warning: {warning}", file=sys.stderr)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
    else:
        for f in findings:
            print(f"{f.severity.upper():<8}  {f.title}")
        print(f"\nLive hosts for the scan context: {', '.join(h['name'] for h in context.live_hosts)}")
    print(f"{len(findings)} subdomain(s) in {elapsed:.0f} s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
