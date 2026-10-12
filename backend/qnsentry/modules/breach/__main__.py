"""Command-line proof of concept for the Breach module.

Run from the backend/ folder:

    python -m qnsentry.modules.breach jan.peeters@badsecurityinc.be sofie.maes@badsecurityinc.be
    python -m qnsentry.modules.breach --from-url https://badsecurityinc-website.vercel.app/team.html
    python -m qnsentry.modules.breach --json --dataset path/to/breaches.json jan.peeters@badsecurityinc.be

--from-url takes the mailto: addresses of one page, standing in for the Metadata module (#8).
Only check addresses of organisations you are allowed to assess.
"""

import argparse
import json
import re
import sys
import urllib.request
from dataclasses import asdict

from qnsentry.modules.base import ScanContext
from qnsentry.modules.breach import BreachModule
from qnsentry.modules.breach.sources import get_breach_source

MAILTO = re.compile(r"mailto:([^\"'?>\s]+)", re.IGNORECASE)


def addresses_on_page(url: str) -> list[str]:
    request = urllib.request.Request(url, headers={"User-Agent": "QN-Sentry breach check"})
    with urllib.request.urlopen(request, timeout=20) as response:
        page = response.read().decode("utf-8", errors="replace")
    return sorted({m.lower() for m in MAILTO.findall(page)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m qnsentry.modules.breach",
        description="Check business email addresses against a breach source (issue #11).",
    )
    parser.add_argument("emails", nargs="*", help="email addresses to check")
    parser.add_argument("--from-url", help="also check the mailto: addresses on this web page")
    parser.add_argument("--source", default="local", help="breach source: local (default) or hibp")
    parser.add_argument("--dataset", help="JSON dataset for the local source (default: the BadSecurityInc test data)")
    parser.add_argument("--json", action="store_true", help="print the findings in the data contract format")
    args = parser.parse_args(argv)

    emails = list(args.emails)
    if args.from_url:
        found = addresses_on_page(args.from_url)
        print(f"Found {len(found)} address(es) on {args.from_url}", file=sys.stderr)
        emails += found
    if not emails:
        parser.error("give at least one email address or --from-url")

    try:
        module = BreachModule(lambda: get_breach_source(args.source, args.dataset))
        context = ScanContext(domain="", emails=emails)
        findings = module.run(context)
    except (RuntimeError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    for warning in context.warnings:
        print(f"Warning: {warning}", file=sys.stderr)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
    else:
        for f in findings:
            breaches = ", ".join(b["name"] for b in f.details["breaches"])
            print(f"{f.severity.upper():<8}  {f.asset:<40}  {breaches}")
    print(f"{len(findings)} of {len(set(e.lower() for e in emails))} address(es) found in breaches", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
