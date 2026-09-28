"""Command-line proof of concept for the phishing module.

Run from the backend/ folder:

    python -m qnsentry.modules.phishing badsecurityinc.be
    python -m qnsentry.modules.phishing badsecurityinc.be --json
    python -m qnsentry.modules.phishing badsecurityinc.be --nameservers 1.1.1.1

Only scan domains you own or have written permission to assess.
"""

import argparse
import json
from dataclasses import asdict
import sys
import time

from qnsentry.modules.phishing.lookalikes import find_lookalike_domains, generate_permutations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m qnsentry.modules.phishing",
        description="Find registered lookalike domains of a domain (issue #9).",
    )
    parser.add_argument("domain", help="the client's domain, e.g. badsecurityinc.be")
    parser.add_argument("--json", action="store_true", help="print the findings in the data contract format")
    parser.add_argument("--threads", type=int, default=16, help="parallel DNS lookups (default: 16)")
    parser.add_argument(
        "--nameservers",
        help="comma-separated DNS servers to use instead of the system resolver, e.g. 1.1.1.1,9.9.9.9",
    )
    args = parser.parse_args(argv)
    nameservers = [ns.strip() for ns in args.nameservers.split(",")] if args.nameservers else None

    try:
        candidates = len(generate_permutations(args.domain)) - 1  # minus the original
    except ValueError as e:
        parser.error(str(e))

    print(f"Checking {candidates} lookalike candidates of {args.domain} ...", file=sys.stderr)
    started = time.monotonic()
    try:
        findings = find_lookalike_domains(args.domain, threads=args.threads, nameservers=nameservers)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
    else:
        for f in findings:
            mx = ", ".join(f.details["mx"]) or "-"
            print(f"{f.severity.upper():<8}  {f.asset:<40}  {f.details['fuzzer']:<14}  MX: {mx}")

    print(f"{len(findings)} registered lookalike domain(s) found in {elapsed:.0f} s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
