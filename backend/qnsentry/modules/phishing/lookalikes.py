"""Lookalike domain detection (issue #9) with dnstwist.

Three steps:
1. Generate permutations of the client's domain: typos, homoglyphs, extra letters, ...
   (dnstwist.Fuzzer, offline)
2. Look up the DNS records (NS, A, AAAA, MX) of every permutation to see which ones
   are registered (dnstwist.Scanner threads)
3. Turn every registered lookalike into a finding

Only DNS lookups are done, so the module stays passive: no banner grabbing, WHOIS or
fetching web pages, which would contact servers of third parties.

We call Fuzzer and Scanner directly instead of dnstwist.run(): run() rewrites sys.argv
and installs its own SIGINT/SIGTERM handlers, which would interfere with the Celery worker.
dnstwist's version is pinned in requirements.txt because Scanner is not an official API.
"""

import queue
from typing import Any

import dns.exception
import dns.resolver
import dnstwist

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding

MODULE = "phishing"
FINDING_TYPE = "lookalike_domain"
DNS_FIELDS = ("dns_ns", "dns_a", "dns_aaaa", "dns_mx")
SERVFAIL = "!ServFail"  # dnstwist's marker for a failed lookup; not a real record

Permutation = dict[str, Any]


def find_lookalike_domains(
    domain: str, *, threads: int = 16, nameservers: list[str] | None = None
) -> list[Finding]:
    """All registered lookalikes of `domain` as findings, those that can receive email first."""
    permutations = resolve_permutations(domain, threads=threads, nameservers=nameservers)
    return [to_finding(p) for p in registered_lookalikes(domain, permutations)]


def generate_permutations(domain: str) -> list[Permutation]:
    """Step 1: the lookalike candidates, without any network traffic."""
    fuzzer = _fuzzer(domain)
    return fuzzer.permutations()


def resolve_permutations(
    domain: str, *, threads: int = 16, nameservers: list[str] | None = None
) -> list[Permutation]:
    """Step 2: every permutation with the DNS records that were found for it."""
    if not dnstwist.MODULE_DNSPYTHON:
        # Without dnspython dnstwist falls back to plain A lookups and never sees MX records
        raise RuntimeError("dnspython is not installed; it is needed for NS and MX lookups")

    fuzzer = _fuzzer(domain)
    check_resolver(fuzzer.tld, nameservers)
    jobs: queue.Queue = queue.Queue()
    for permutation in fuzzer.domains:
        jobs.put(permutation)

    workers = []
    for _ in range(threads):
        worker = dnstwist.Scanner(jobs)
        worker.option_extdns = True
        if nameservers:
            worker.nameservers = nameservers
        worker.start()
        workers.append(worker)
    # A Scanner stops by itself when the queue is empty
    for worker in workers:
        worker.join()

    return fuzzer.permutations(dns_all=True)


def registered_lookalikes(domain: str, permutations: list[Permutation]) -> list[Permutation]:
    """Step 3a: keep the registered lookalikes, those with a mail server first."""
    original = domain.lower().rstrip(".")
    found = [
        p
        for p in permutations
        if p.get("fuzzer") != "*original" and p["domain"] != original and _is_registered(p)
    ]
    return sorted(found, key=lambda p: (not _records(p, "dns_mx"), p["domain"]))


def to_finding(permutation: Permutation) -> Finding:
    """Step 3b: one registered lookalike as a finding (severity rules: data contract 10.2)."""
    name = permutation["domain"]
    readable = _unicode(name)
    mx = _records(permutation, "dns_mx")

    if mx:
        severity = Severity.HIGH
        title = f"Registered lookalike domain {readable} (can receive email)"
        description = (
            "This domain looks like the company domain and has a mail server. It can be used "
            "to send phishing emails to employees and customers that are hard to tell apart "
            "from real ones, and to receive their replies."
        )
    else:
        severity = Severity.LOW
        title = f"Registered lookalike domain {readable}"
        description = (
            "This domain looks like the company domain and has been registered by someone. "
            "It has no mail server yet, but it can host a phishing website or be set up for "
            "email later."
        )

    details: dict[str, Any] = {
        "fuzzer": permutation.get("fuzzer"),
        "ns": _records(permutation, "dns_ns"),
        "a": _records(permutation, "dns_a"),
        "aaaa": _records(permutation, "dns_aaaa"),
        "mx": mx,
    }
    if readable != name:
        details["unicode"] = readable

    return Finding(
        module=MODULE,
        type=FINDING_TYPE,
        title=title,
        description=description,
        severity=severity,
        asset=name,
        details=details,
    )


def check_resolver(tld: str, nameservers: list[str] | None = None) -> None:
    """Fail loudly when the DNS resolver cannot be trusted.

    Some resolvers (filtering routers, sandboxes) answer "does not exist" for ordinary
    domains. dnstwist would then report zero lookalikes, which looks like a clean result
    but means nothing was checked. So we first look up two names that always exist: the
    nameservers of the top-level domain, and the address of one of those nameservers
    (an ordinary hostname like a.nsset.be). If the resolver denies either, the module
    raises instead (data contract 10.3.1: total failure).
    """
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    resolver.lifetime = 10
    try:
        tld_nameservers = sorted(str(r.target) for r in resolver.resolve(f"{tld}.", "NS"))
        resolver.resolve(tld_nameservers[0], "A")
    except dns.exception.DNSException as e:
        raise RuntimeError(
            f"The DNS resolver {', '.join(resolver.nameservers)} does not resolve names that must "
            f"exist ({type(e).__name__}), so lookalike results would be unreliable. "
            "Use another resolver, e.g. nameservers=['1.1.1.1']."
        ) from e


def _fuzzer(domain: str) -> dnstwist.Fuzzer:
    try:
        url = dnstwist.UrlParser(domain)
    except ValueError as e:
        raise ValueError(f"Not a valid domain name: {domain!r}") from e
    fuzzer = dnstwist.Fuzzer(url.domain)
    fuzzer.generate()
    return fuzzer


def _records(permutation: Permutation, field: str) -> list[str]:
    # Drops failed lookups and the empty name of a "null MX" (a domain that refuses email)
    return [r for r in permutation.get(field, []) if r and r != SERVFAIL]


def _is_registered(permutation: Permutation) -> bool:
    return any(_records(permutation, field) for field in DNS_FIELDS)


def _unicode(name: str) -> str:
    """xn--bdsecurityinc-bfb.be -> bädsecurityinc.be, so homoglyphs are readable in reports."""
    try:
        return name.encode("ascii").decode("idna")
    except UnicodeError:
        return name
