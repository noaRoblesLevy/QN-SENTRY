"""Email security of the client's own domain (issue #29): SPF, DMARC and DKIM.

Without these DNS records, or with weak ones, anyone can send email that appears to
come from the company's own domain (email spoofing). That makes phishing aimed at
employees and customers far more convincing.

- SPF (TXT on the domain): which servers may send mail for the domain. It may need at
  most 10 DNS lookups, counted through its included records (#44)
- DMARC (TXT on _dmarc.<domain>): what a receiving mail server must do with mail that
  fails the checks; only p=quarantine and p=reject actually stop spoofed mail
- DKIM (TXT on <selector>._domainkey.<domain>): public keys to verify signed mail.
  Selectors cannot be listed through DNS, so only common selectors are checked.

The evaluate_* functions only interpret record text, so they are tested without network.
"""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding
from qnsentry.modules.phishing.constants import MODULE

log = logging.getLogger(__name__)

FINDING_TYPE = "email_security"
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail")
# RFC 7208 4.6.4: evaluating SPF may cause at most 10 DNS lookups; above that the result is
# a permerror and receiving mail servers ignore SPF
SPF_LOOKUP_LIMIT = 10
SPF_LOOKUP_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


class LookupFailed(Exception):
    """A DNS lookup gave no usable answer (timeout, server failure), so the result is unknown."""


@dataclass
class SpfResult:
    findings: list[Finding] = field(default_factory=list)
    # True when SPF does not stop anyone: missing, or explicitly allowing every server
    allows_everyone: bool = False


def check_email_security(
    domain: str,
    *,
    nameservers: list[str] | None = None,
    timeout: float = 5.0,
    warn: Callable[[str], None] = lambda message: None,
) -> list[Finding]:
    """SPF, DMARC and DKIM findings for `domain`.

    A failing lookup skips only that check (data contract 10.3.1: partial failure).
    If SPF and DMARC both fail, the resolver is unusable and the function raises.
    Skipped checks are reported to `warn`.
    """
    resolver = _resolver(nameservers, timeout)
    findings: list[Finding] = []
    failed: list[str] = []

    spf = SpfResult()
    spf_records: list[str] = []
    try:
        spf_records = [r for r in txt_records(resolver, domain) if _is_spf(r)]
        spf = evaluate_spf(domain, spf_records)
        findings += spf.findings
    except LookupFailed as e:
        log.warning("SPF check of %s skipped: %s", domain, e)
        warn("The SPF record could not be looked up, so SPF was not checked")
        failed.append("SPF")

    if len(spf_records) == 1:
        try:
            lookups = count_spf_lookups(domain, spf_records[0], lambda name: txt_records(resolver, name))
            ignored = evaluate_spf_lookups(domain, lookups)
            findings += ignored
            if ignored:
                # Receivers ignore this SPF record, so it stops nobody: DMARC weighs that in
                spf.allows_everyone = True
        except LookupFailed as e:
            log.warning("SPF lookup count of %s skipped: %s", domain, e)
            warn(
                "A record included by the SPF record could not be looked up, so the 10-lookup "
                "limit of SPF was not checked"
            )

    try:
        dmarc_records = txt_records(resolver, f"_dmarc.{domain}")
        findings += evaluate_dmarc(domain, dmarc_records, spf_allows_everyone=spf.allows_everyone)
    except LookupFailed as e:
        log.warning("DMARC check of %s skipped: %s", domain, e)
        warn("The DMARC record could not be looked up, so DMARC was not checked")
        failed.append("DMARC")

    if len(failed) == 2:
        # Both lookups failed, so the resolver is not answering: stop before trying
        # every DKIM selector, which would only add one timeout per selector
        raise RuntimeError(f"Email security of {domain} could not be checked: the SPF and DMARC lookups failed")

    try:
        findings += evaluate_dkim(domain, dkim_keys(resolver, domain))
    except LookupFailed as e:
        log.warning("DKIM check of %s skipped: %s", domain, e)
        warn("The DKIM records could not be looked up, so DKIM was not checked")

    return findings


# ---------- DNS lookups ----------


def txt_records(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    """All TXT records of `name` as text; [] when the name or record does not exist."""
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as e:
        raise LookupFailed(f"{name}: {type(e).__name__}") from e
    # A TXT record can be split into several strings of at most 255 characters
    return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answer]


def dkim_keys(resolver: dns.resolver.Resolver, domain: str) -> dict[str, str]:
    """DKIM records found per selector. Raises only when every selector lookup failed."""
    found: dict[str, str] = {}
    failures = 0
    for selector in DKIM_SELECTORS:
        try:
            records = txt_records(resolver, f"{selector}._domainkey.{domain}")
        except LookupFailed:
            failures += 1
            continue
        for record in records:
            if _is_dkim_key(record):
                found[selector] = record
                break
    if failures == len(DKIM_SELECTORS):
        raise LookupFailed(f"every DKIM selector lookup for {domain} failed")
    return found


# ---------- Interpretation ----------


def evaluate_spf(domain: str, txt: list[str]) -> SpfResult:
    spf_records = [r for r in txt if _is_spf(r)]

    if not spf_records:
        return SpfResult(
            [
                _finding(
                    domain,
                    f"No SPF record on {domain}",
                    "The domain does not say which servers may send its email, so receiving mail "
                    "servers cannot recognise mail from other servers as fake. Add an SPF record; a "
                    "domain that sends no email at all can use 'v=spf1 -all'.",
                    Severity.MEDIUM,
                    {"check": "spf", "record": None},
                )
            ],
            allows_everyone=True,
        )

    if len(spf_records) > 1:
        return SpfResult(
            [
                _finding(
                    domain,
                    f"Multiple SPF records on {domain}",
                    "The domain has more than one SPF record. Receiving mail servers treat that as "
                    "an error and ignore SPF, so it does not protect against spoofed email. Merge "
                    "them into one record.",
                    Severity.MEDIUM,
                    {"check": "spf", "records": spf_records},
                )
            ]
        )

    record = spf_records[0]
    qualifier = spf_all_qualifier(record)
    details = {"check": "spf", "record": record, "all": qualifier}

    if qualifier in ("+all", "all"):
        return SpfResult(
            [
                _finding(
                    domain,
                    f"SPF record allows every server to send email for {domain}",
                    f"The SPF record ends in '{qualifier}', which explicitly authorises every server "
                    "in the world to send email as this domain. The domain can be spoofed and the "
                    "fake mail even passes the SPF check. Replace it with '-all' and list only the "
                    "real mail servers.",
                    Severity.HIGH,
                    details,
                )
            ],
            allows_everyone=True,
        )
    if qualifier == "~all":
        return SpfResult(
            [
                _finding(
                    domain,
                    f"Weak SPF policy on {domain} (~all)",
                    "Mail from servers that are not listed only 'soft fails': receiving mail servers "
                    "are asked to be suspicious but usually still deliver it. On its own this does "
                    "not stop spoofing; a strict DMARC policy or '-all' does.",
                    Severity.LOW,
                    details,
                )
            ]
        )
    if qualifier == "-all":
        return SpfResult()
    if qualifier is None and "redirect=" in record.lower():
        # The policy lives in another domain's record; following it is out of scope for now
        return SpfResult()

    # ?all, or no 'all' at all: the result for unlisted servers is "neutral"
    return SpfResult(
        [
            _finding(
                domain,
                f"SPF record on {domain} does not reject other servers",
                "The SPF record does not end in '-all', so mail from servers that are not listed is "
                "treated as neutral instead of fake. The domain can be spoofed. End the record with "
                "'-all'.",
                Severity.MEDIUM,
                details,
            )
        ]
    )


@dataclass
class SpfLookups:
    count: int = 0
    # Records that were followed, in order: the domain itself, then includes and redirects
    followed: list[str] = field(default_factory=list)
    # A record that (indirectly) includes itself; real mail servers hit the limit on it
    loop: str | None = None
    # An include: or redirect= target without exactly one SPF record (RFC 7208 5.2, 6.1),
    # with what is wrong: "has no SPF record" or "has 2 SPF records"
    broken: tuple[str, str] | None = None

    @property
    def permerror(self) -> bool:
        """True when receivers stop evaluating with a permanent error and ignore SPF."""
        return self.count > SPF_LOOKUP_LIMIT or self.loop is not None or self.broken is not None


def count_spf_lookups(domain: str, record: str, get_txt: Callable[[str], list[str]]) -> SpfLookups:
    """The DNS lookups evaluating `record` costs, counted through include: and redirect=.

    Counts the terms that need a lookup (include, a, mx, ptr, exists, redirect); ip4, ip6
    and all do not. Stops at the first permanent error (over the limit, a loop, or an
    included record that does not exist), so a huge or looping tree of records cannot
    make the check slow. `get_txt` returns the TXT records of a name.

    The count is the worst case, like common SPF checkers: a receiver stops at the first
    term that matches the sender, so mail from a server listed early may never reach it.
    """
    result = SpfLookups()

    def walk(name: str, spf: str, path: tuple[str, ...]) -> None:
        result.followed.append(name)
        terms = [t.lower() for t in spf.split()[1:]]
        # redirect= only applies when the record has no 'all' (RFC 7208 6.1)
        has_all = any(t.lstrip("+-~?") == "all" for t in terms)
        for term in terms:
            if result.permerror:
                return
            mechanism, target = _spf_term(term)
            if mechanism not in SPF_LOOKUP_TERMS or (mechanism == "redirect" and has_all):
                continue
            result.count += 1
            if result.count > SPF_LOOKUP_LIMIT:
                return  # the verdict is known; following this include would be one lookup too many
            if mechanism not in ("include", "redirect") or not target or "%" in target:
                continue  # no record to follow; names with macros (%{i}) depend on the sender
            if target in path:
                result.loop = target
                return
            included = [r for r in get_txt(target) if _is_spf(r)]
            if len(included) != 1:
                problem = "has no SPF record" if not included else f"has {len(included)} SPF records"
                result.broken = (f"{mechanism}:{target}" if mechanism == "include" else f"redirect={target}", problem)
                return
            walk(target, included[0], path + (target,))

    walk(domain.lower(), record, (domain.lower(),))
    return result


def evaluate_spf_lookups(domain: str, lookups: SpfLookups) -> list[Finding]:
    """A finding when receivers ignore the SPF record because evaluating it ends in a
    permanent error (permerror): too many lookups, a loop, or a broken include."""
    if not lookups.permerror:
        return []

    if lookups.broken:
        term, problem = lookups.broken
        reason, title_reason = "broken_include", f"{term} {problem}"
        cause = (
            f"The record refers to {term}, which {problem}. Receiving mail servers treat that as "
            "an error (permerror). This often happens when a company stops using a mail service "
            "and the service removes its record, but the include stays. Remove the include, or "
            "fix the record it points to."
        )
    elif lookups.loop:
        reason, title_reason = "loop", f"the included records form a loop ({lookups.loop} includes itself)"
        cause = (
            f"The included records refer back to {lookups.loop}, so evaluating them never ends. "
            "Receiving mail servers stop at the lookup limit and treat it as an error (permerror). "
            "Remove the include that points back."
        )
    else:
        reason, title_reason = "too_many_lookups", f"it needs more than {SPF_LOOKUP_LIMIT} DNS lookups"
        cause = (
            f"Receiving mail servers do at most {SPF_LOOKUP_LIMIT} DNS lookups to evaluate an SPF "
            "record, counting every include, a, mx, ptr, exists and redirect, also inside the "
            f"included records. The SPF record of {domain} needs more in the worst case (a server "
            "listed early can still pass, but mail from the others fails), so mail servers treat it "
            "as an error (permerror). This often happens when several mail services are added "
            "(Microsoft 365, a newsletter tool, a CRM). Remove services that are no longer used, or "
            "replace includes with the ip4/ip6 ranges they stand for."
        )

    return [
        _finding(
            domain,
            f"SPF record on {domain} is ignored: {title_reason}",
            f"{cause} An ignored SPF record does not protect against spoofed email, even when it "
            "ends in '-all'.",
            Severity.MEDIUM,
            {
                "check": "spf_permerror",
                "reason": reason,
                "lookups": lookups.count if reason == "too_many_lookups" else None,
                "limit": SPF_LOOKUP_LIMIT,
                "followed": lookups.followed,
                "loop": lookups.loop,
                "broken": lookups.broken[0] if lookups.broken else None,
            },
        )
    ]


def spf_all_qualifier(record: str) -> str | None:
    """The 'all' mechanism at the end of an SPF record: '+all', 'all', '-all', '~all', '?all' or None."""
    for term in record.lower().split():
        if term.lstrip("+-~?") == "all":
            return term
    return None


def parse_dmarc(record: str) -> dict[str, str]:
    """'v=DMARC1; p=none; pct=100' -> {'v': 'DMARC1', 'p': 'none', 'pct': '100'}"""
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def evaluate_dmarc(domain: str, txt: list[str], *, spf_allows_everyone: bool = False) -> list[Finding]:
    records = [r for r in txt if r.replace(" ", "").lower().startswith("v=dmarc1")]
    # Spoofing is worst when neither SPF nor DMARC stops it (open question 10.6: combinations)
    unprotected = Severity.HIGH if spf_allows_everyone else Severity.MEDIUM
    spf_note = (
        " SPF does not stop spoofed mail either, so nothing on this domain does."
        if spf_allows_everyone
        else ""
    )

    if not records:
        return [
            _finding(
                domain,
                f"No DMARC record on {domain}",
                "Without DMARC, receiving mail servers are not told to block mail that fails the SPF "
                "and DKIM checks, so email that appears to come from this domain is usually "
                f"delivered. The domain can be spoofed.{spf_note} Add a DMARC record with "
                "'p=quarantine' or 'p=reject'.",
                unprotected,
                {"check": "dmarc", "record": None},
            )
        ]

    if len(records) > 1:
        return [
            _finding(
                domain,
                f"Multiple DMARC records on {domain}",
                "The domain has more than one DMARC record. Receiving mail servers then ignore DMARC "
                f"completely, so the domain can be spoofed.{spf_note} Keep one record.",
                unprotected,
                {"check": "dmarc", "records": records},
            )
        ]

    record = records[0]
    tags = parse_dmarc(record)
    policy = tags.get("p", "").lower()
    pct = tags.get("pct", "100")
    details = {"check": "dmarc", "record": record, "policy": policy or None, "pct": pct}

    if policy == "none":
        return [
            _finding(
                domain,
                f"DMARC policy p=none on {domain}: spoofed email is delivered",
                "The DMARC policy 'p=none' only asks for reports: receiving mail servers are told to "
                f"deliver mail that fails the checks anyway. The domain can be spoofed.{spf_note} "
                "Change the policy to 'p=quarantine' or 'p=reject'.",
                unprotected,
                details,
            )
        ]
    if policy == "quarantine":
        return [
            _finding(
                domain,
                f"DMARC policy p=quarantine on {domain}: spoofed email goes to spam",
                "Mail that fails the checks is put in the spam folder instead of being rejected. "
                "Spoofing is mostly stopped, but fake mail can still reach users who check their "
                "spam folder. 'p=reject' blocks it completely.",
                Severity.LOW,
                details,
            )
        ]
    if policy == "reject":
        if pct != "100":
            return [
                _finding(
                    domain,
                    f"DMARC policy on {domain} applies to only {pct}% of email",
                    f"The policy 'p=reject' is set, but 'pct={pct}' applies it to only part of the "
                    "mail that fails the checks; the rest is delivered. Remove 'pct' or set it to 100.",
                    Severity.LOW,
                    details,
                )
            ]
        return []

    return [
        _finding(
            domain,
            f"Invalid DMARC record on {domain}",
            "The DMARC record has no valid policy ('p=none', 'quarantine' or 'reject'), so receiving "
            f"mail servers ignore it and the domain can be spoofed.{spf_note}",
            unprotected,
            details,
        )
    ]


def evaluate_dkim(domain: str, keys: dict[str, str]) -> list[Finding]:
    checked = list(DKIM_SELECTORS)
    if keys:
        selectors = ", ".join(sorted(keys))
        return [
            _finding(
                domain,
                f"DKIM keys found on {domain} ({selectors})",
                "The domain publishes DKIM keys, so receiving mail servers can verify that its mail "
                "is signed by the domain. Together with a strict DMARC policy this stops spoofing.",
                Severity.INFO,
                {"check": "dkim", "selectors_found": sorted(keys), "selectors_checked": checked},
            )
        ]
    return [
        _finding(
            domain,
            f"No DKIM key found on {domain} for common selectors",
            "No DKIM key was found under the usual names. Without DKIM, receiving mail servers "
            "cannot verify that mail was really signed by this domain, and protection against "
            "spoofing depends on SPF alone, which breaks when mail is forwarded. The domain may use "
            "a custom selector that cannot be discovered through DNS, so check the mail provider's "
            "settings.",
            Severity.LOW,
            {"check": "dkim", "selectors_found": [], "selectors_checked": checked},
        )
    ]


# ---------- Helpers ----------


def _finding(domain: str, title: str, description: str, severity: Severity, details: dict) -> Finding:
    return Finding(
        module=MODULE,
        type=FINDING_TYPE,
        title=title,
        description=description,
        severity=severity,
        asset=domain,
        details=details,
    )


def _is_spf(record: str) -> bool:
    return record.lower().startswith("v=spf1")


def _spf_term(term: str) -> tuple[str, str | None]:
    """'~include:_spf.google.com' -> ('include', '_spf.google.com'); 'redirect=x.be' -> ('redirect', 'x.be')"""
    if term.startswith("redirect="):
        return "redirect", term.split("=", 1)[1]
    body = term.lstrip("+-~?")
    mechanism = re.split(r"[:/=]", body, maxsplit=1)[0]
    target = body.split(":", 1)[1].split("/")[0] if ":" in body else None
    return mechanism, target


def _is_dkim_key(record: str) -> bool:
    # DKIM uses the same "tag=value;" syntax as DMARC. The key is in p=; an empty p= means revoked.
    return bool(parse_dmarc(record).get("p"))


def _resolver(nameservers: list[str] | None, timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver
