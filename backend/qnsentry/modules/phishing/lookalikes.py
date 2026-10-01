"""Lookalike domain detection (issue #9) with dnstwist.

Three steps:
1. Generate permutations of the client's domain: typos, homoglyphs, extra letters,
   other top-level domains (.com, .eu, ...)
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
from qnsentry.modules.phishing.constants import ALTERNATIVE_TLDS, MODULE

FINDING_TYPE = "lookalike_domain"
DNS_FIELDS = ("dns_ns", "dns_a", "dns_aaaa", "dns_mx")
SERVFAIL = "!ServFail"  # dnstwist's marker for a failed lookup; not a real record

Permutation = dict[str, Any]


def find_lookalike_domains(
    domain: str, *, threads: int = 16, nameservers: list[str] | None = None
) -> list[Finding]:
    """All registered lookalikes of `domain` as findings, those that can receive email first."""
    permutations = resolve_permutations(domain, threads=threads, nameservers=nameservers)
    # The client's own domain is resolved too; its records help to spot its own registrations
    client = next((p for p in permutations if p.get("fuzzer") == "*original"), None)
    return [to_finding(p, client) for p in registered_lookalikes(domain, permutations)]


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
    check_resolver(nameservers)
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


def to_finding(permutation: Permutation, client: Permutation | None = None) -> Finding:
    """Step 3b: one registered lookalike as a finding (severity rules: data contract 10.2).

    `client` is the client's own domain with its DNS records, used to recognise lookalikes
    the client registered itself (defensive registrations).
    """
    name = permutation["domain"]
    readable = _unicode(name)
    mx = _records(permutation, "dns_mx")
    own_infrastructure = _points_into_client_domain(permutation, client)

    if own_infrastructure:
        # Strong evidence: its name servers or mail servers are hosts of the client's own
        # domain, which an outsider cannot set up
        severity = Severity.INFO
        title = f"Lookalike domain {readable} appears to be registered by the company itself"
        description = (
            "This domain looks like the company domain, but its name servers or mail servers are "
            "part of the company's own domain, so it is most likely a defensive registration by "
            "the company. Check that the company really owns it."
        )
    elif mx:
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
    if own_infrastructure:
        details["own_infrastructure"] = own_infrastructure
    else:
        # Weak evidence only: the same DNS or mail provider is shared by many unrelated
        # domains (an attacker can use it too), so it is noted but does not lower the severity
        shared = _shared_with_client(permutation, client)
        if shared:
            details["shared_with_client"] = shared
            description += (
                " It uses the same DNS or mail provider as the company domain; if the company "
                "registered it itself, it can be accepted as a defensive registration."
            )

    return Finding(
        module=MODULE,
        type=FINDING_TYPE,
        title=title,
        description=description,
        severity=severity,
        asset=name,
        details=details,
    )


# A name that exists as long as the internet does: the first root server. Every working
# resolver can answer it, including Docker's built-in DNS (127.0.0.11), which does not
# answer NS queries for a bare top-level domain like "be."
CANARY = ("a.root-servers.net", "A")


def check_resolver(nameservers: list[str] | None = None) -> None:
    """Fail loudly when the DNS resolver cannot be trusted.

    Some resolvers (filtering routers, sandboxes, no network) do not answer or answer
    "does not exist". dnstwist would then report zero lookalikes, which looks like a clean
    result but means nothing was checked. So we first look up a name that always exists;
    if the resolver cannot answer it, the check raises instead (data contract 10.3.1).
    """
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    resolver.lifetime = 10
    try:
        resolver.resolve(*CANARY)
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
    # Without a TLD list dnstwist does not try other TLDs (badsecurityinc.com, .eu, ...).
    # Pass a copy: dnstwist removes the client's own TLD from the list it gets.
    fuzzer = dnstwist.Fuzzer(url.domain, tld_dictionary=list(ALTERNATIVE_TLDS))
    fuzzer.generate()
    return fuzzer


def _is_in_domain(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def _points_into_client_domain(permutation: Permutation, client: Permutation | None) -> dict[str, list[str]]:
    """NS and MX hosts of the lookalike that are part of the client's own domain."""
    if not client:
        return {}
    domain = client["domain"].lower()
    found = {
        "ns": [h for h in _records(permutation, "dns_ns") if _is_in_domain(h, domain)],
        "mx": [h for h in _records(permutation, "dns_mx") if _is_in_domain(h, domain)],
    }
    return {k: v for k, v in found.items() if v}


def _shared_with_client(permutation: Permutation, client: Permutation | None) -> dict[str, list[str]]:
    """NS and MX hosts the lookalike has in common with the client's own domain."""
    if not client:
        return {}
    shared = {
        "ns": sorted(set(_records(permutation, "dns_ns")) & set(_records(client, "dns_ns"))),
        "mx": sorted(set(_records(permutation, "dns_mx")) & set(_records(client, "dns_mx"))),
    }
    return {k: v for k, v in shared.items() if v}


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
