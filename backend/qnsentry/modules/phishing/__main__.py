"""Command-line proof of concept for the phishing module.

Run from the backend/ folder:

    python -m qnsentry.modules.phishing badsecurityinc.be
    python -m qnsentry.modules.phishing badsecurityinc.be --check email
    python -m qnsentry.modules.phishing badsecurityinc.be --check certificates
    python -m qnsentry.modules.phishing badsecurityinc.be --check lookalikes --json
    python -m qnsentry.modules.phishing badsecurityinc.be --nameservers 1.1.1.1

Only scan domains you own or have written permission to assess.
"""

import argparse
import json
import sys
import time
from dataclasses import asdict

from qnsentry.modules.phishing.certificates import find_lookalike_certificates
from qnsentry.modules.phishing.email_security import check_email_security
from qnsentry.modules.phishing.lookalikes import find_lookalike_domains, generate_permutations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m qnsentry.modules.phishing",
        description="Phishing checks for a domain: lookalike domains (#9), their certificates (#10) and email security (#29).",
    )
    parser.add_argument("domain", help="the client's domain, e.g. badsecurityinc.be")
    parser.add_argument(
        "--check",
        choices=["all", "lookalikes", "certificates", "email"],
        default="all",
        help="which check to run; certificates also runs lookalikes, as it needs them (default: all)",
    )
    parser.add_argument("--json", action="store_true", help="print the findings in the data contract format")
    parser.add_argument("--threads", type=int, default=16, help="parallel DNS lookups for lookalikes (default: 16)")
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

    findings = []
    started = time.monotonic()
    try:
        if args.check in ("all", "lookalikes", "certificates"):
            print(f"Checking {candidates} lookalike candidates of {args.domain} ...", file=sys.stderr)
            lookalikes = find_lookalike_domains(args.domain, threads=args.threads, nameservers=nameservers)
            findings += lookalikes
            if args.check in ("all", "certificates"):
                print(f"Searching Certificate Transparency for {len(lookalikes)} lookalike(s) ...", file=sys.stderr)
                findings += find_lookalike_certificates(lookalikes)
        if args.check in ("all", "email"):
            print(f"Checking SPF, DMARC and DKIM of {args.domain} ...", file=sys.stderr)
            findings += check_email_security(args.domain, nameservers=nameservers)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
    else:
        for f in findings:
            print(f"{f.severity.upper():<8}  {f.type:<21}  {f.title}")

    print(f"{len(findings)} finding(s) in {elapsed:.0f} s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
