"""Command-line proof of concept for the metadata module.

Run from the backend/ folder (katana and exiftool must be installed, e.g. in the worker):

    python -m qnsentry.modules.metadata badsecurityinc.be
    python -m qnsentry.modules.metadata --start-url https://badsecurityinc-website.vercel.app
    python -m qnsentry.modules.metadata badsecurityinc.be --json

Only crawl websites you own or have written permission to assess.
"""

import argparse
import json
import sys
import time
from dataclasses import asdict

from qnsentry.modules.base import ScanContext
from qnsentry.modules.metadata import analyse_site
from qnsentry.modules.metadata.crawler import start_urls


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m qnsentry.modules.metadata",
        description="Find public documents on a website and analyse their metadata (issue #7).",
    )
    parser.add_argument("domain", nargs="?", help="the client's domain, e.g. badsecurityinc.be")
    parser.add_argument("--start-url", help="crawl this URL instead of https://<domain> and https://www.<domain>")
    parser.add_argument("--json", action="store_true", help="print the findings in the data contract format")
    args = parser.parse_args(argv)

    if args.start_url:
        urls = [args.start_url]
    elif args.domain:
        urls = start_urls(args.domain)
    else:
        parser.error("give a domain or --start-url")

    print(f"Crawling {', '.join(urls)} ...", file=sys.stderr)
    context = ScanContext(domain=args.domain or "")
    started = time.monotonic()
    try:
        findings = analyse_site(urls, context)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
    else:
        for f in findings:
            print(f"{f.severity.upper():<8}  {f.title}")
        if context.person_names:
            print(f"\nPeople for the scan context: {', '.join(context.person_names)}")
    print(f"{len(findings)} document(s) with metadata findings in {elapsed:.0f} s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
