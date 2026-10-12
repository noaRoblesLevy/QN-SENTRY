"""Domain ownership verification with a DNS TXT record (issue #48).

Before a domain can be scanned, the client proves it controls the domain's DNS by adding
a TXT record to it:

    badsecurityinc.be.  TXT  "qn-sentry-verify=<token>"

Only someone who manages the domain can add that record, so a scan can no longer be
started for a domain of someone else (legal framework 5.1).

The token is an HMAC of the domain name with DOMAIN_VERIFICATION_SECRET. It is not stored:
- the same secret always gives the same token, so one TXT record keeps working after the
  database is emptied, on a new demo laptop or in a fresh test installation;
- without the secret the token cannot be predicted, and another installation (with
  another secret) gets another token, so a record made for one installation does not
  verify the domain on another.
"""

import hashlib
import hmac

import dns.exception
import dns.resolver

PREFIX = "qn-sentry-verify="
TOKEN_LENGTH = 32  # hex characters (128 bits)


class VerificationLookupFailed(Exception):
    """The TXT records could not be looked up (timeout, server failure): try again later."""


def verification_token(domain: str, secret: str) -> str:
    digest = hmac.new(secret.encode(), domain.lower().rstrip(".").encode(), hashlib.sha256)
    return digest.hexdigest()[:TOKEN_LENGTH]


def verification_record(domain: str, secret: str) -> str:
    """The value of the TXT record the client adds to `domain`."""
    return f"{PREFIX}{verification_token(domain, secret)}"


def has_verification_record(txt_records: list[str], expected: str) -> bool:
    """True when one of the TXT records is exactly the expected value.

    DNS providers sometimes show TXT values with quotes or spaces around them, and a long
    value can be split into several strings; txt_records() already joins those strings.
    """
    return any(record.strip().strip('"').strip() == expected for record in txt_records)


def txt_records(domain: str, *, nameservers: list[str] | None = None, timeout: float = 5.0) -> list[str]:
    """All TXT records of `domain` as text; [] when the domain or the record does not exist."""
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    try:
        answer = resolver.resolve(domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as error:
        raise VerificationLookupFailed(f"{domain}: {type(error).__name__}") from error
    return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answer]
