"""Breach sources: where the Breach module looks up email addresses (issue #11).

A source answers one question: in which known data breaches does this address appear?
It is pluggable, so the module does not change when the source does:

- LocalDatasetSource: a JSON file with fictitious breaches, for the demo and tests (#11)
- HibpSource: the Have I Been Pwned API, the real-world source (#13)

The shape of a breach follows the Have I Been Pwned API, so both sources return the same.
Data minimisation (docs/project/05-legal-ethical.md): a source only returns the breach
name, date and the *kinds* of data exposed, never the leaked data itself.
"""

import json
import os
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

# The fictitious breaches of the BadSecurityInc test environment
DEFAULT_DATASET = Path(__file__).resolve().parent / "testdata" / "breaches.json"


# Flags of a breach, following the Have I Been Pwned breach model
SPAM_LIST = "spam_list"  # a list of addresses, not the result of a security compromise
FABRICATED = "fabricated"  # probably fake data, not a real breach
UNVERIFIED = "unverified"  # HIBP could not confirm the breach is genuine
MALWARE = "malware"  # credentials stolen by malware on the victim's own device (incl. stealer logs)


@dataclass(frozen=True)
class Breach:
    name: str
    date: str  # YYYY-MM-DD
    data_classes: tuple[str, ...]  # kinds of data exposed, e.g. ("Email addresses", "Passwords")
    flags: frozenset[str] = frozenset()


class LookupUnavailable(RuntimeError):
    """This address could not be checked right now (server error, timeout, rate limit).

    Other addresses may still work, so the module skips this one instead of failing.
    Errors that affect every lookup (invalid API key, access denied) are a plain
    RuntimeError and fail the module.
    """


class BreachSource(ABC):
    # Shown with the findings when the source's terms of use require it
    attribution: str | None = None
    # A limitation of the source the reader should know, added to the description
    note: str | None = None

    @abstractmethod
    def lookup(self, email: str) -> list[Breach]:
        """The breaches `email` appears in; [] when it appears in none."""


class LocalDatasetSource(BreachSource):
    """Breaches from a JSON file: a catalogue of breaches, and per address the breach names.

    {"breaches": {"ExampleShop": {"date": "2021-06-22", "data_classes": [...], "flags": [...]}},
     "accounts": {"jan.peeters@badsecurityinc.be": ["ExampleShop"]}}

    "flags" is optional and uses the names above (e.g. "spam_list").
    """

    def __init__(self, path: Path | str = DEFAULT_DATASET):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise RuntimeError(f"Breach dataset {path} could not be read: {e}") from e

        catalogue = {
            name: Breach(
                name=name,
                date=entry["date"],
                data_classes=tuple(entry["data_classes"]),
                flags=frozenset(entry.get("flags", [])),
            )
            for name, entry in data["breaches"].items()
        }
        self.accounts: dict[str, list[Breach]] = {}
        for email, names in data["accounts"].items():
            unknown = [n for n in names if n not in catalogue]
            if unknown:
                raise RuntimeError(f"Breach dataset {path}: {email} refers to unknown breaches {unknown}")
            self.accounts[email.lower()] = [catalogue[n] for n in names]

    def lookup(self, email: str) -> list[Breach]:
        return list(self.accounts.get(email.strip().lower(), []))


class HibpSource(BreachSource):
    """The Have I Been Pwned API v3 (https://haveibeenpwned.com/API/v3#BreachesForAccount).

    - The API key comes from configuration (HIBP_API_KEY) and is sent in the hibp-api-key header.
    - 404 means the address is in no breach, which is a normal answer, not an error.
    - The key's plan allows a number of requests per minute. We wait `min_interval` seconds
      between requests so we stay under it, and when HIBP still answers 429 (too many
      requests) we wait the Retry-After seconds it asks for and try again.
      The pause is kept per scan. The worker runs two scans at once (--concurrency=2), so
      with two HIBP scans at the same time set HIBP_MIN_INTERVAL_SECONDS to twice the
      plan's interval (12 instead of 6 for 10 requests per minute).
    - Errors for one address (server error or timeout after one retry, rate limit after
      retrying, invalid address) raise LookupUnavailable: the module skips that address.
      Errors that affect every lookup (401 invalid key, 403 denied) raise RuntimeError
      and fail the module.
    - The breach flags are kept: spam lists, fabricated, unverified and malware breaches
      are weighed differently (see the module).
    - Privacy: only the email address is sent, to a service outside the EU (legal
      framework 5.3). The default source is the local dataset.
    """

    URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false"
    attribution = "Breach data from Have I Been Pwned (https://haveibeenpwned.com), CC BY 4.0"
    note = (
        "Have I Been Pwned does not return sensitive breaches (such as adult websites) through "
        "this search, so the list of breaches can be incomplete."
    )
    USER_AGENT = "QN-Sentry OSINT risk assessment"  # HIBP refuses requests without one

    def __init__(
        self,
        api_key: str,
        *,
        min_interval: float = 6.0,
        max_retries: int = 3,
        transient_retries: int = 1,
        transient_wait: float = 2.0,
        opener: Callable = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not api_key:
            raise RuntimeError("The Have I Been Pwned source needs an API key: set HIBP_API_KEY")
        self.api_key = api_key
        self.min_interval = min_interval
        self.max_retries = max_retries
        self.transient_retries = transient_retries
        self.transient_wait = transient_wait
        self.opener, self.sleep, self.clock = opener, sleep, clock
        self._last_request: float | None = None

    def lookup(self, email: str) -> list[Breach]:
        request = urllib.request.Request(
            self.URL.format(quote(email.strip().lower(), safe="")),
            headers={"hibp-api-key": self.api_key, "user-agent": self.USER_AGENT},
        )
        rate_limited = transient = 0
        while True:
            self._wait_for_rate_limit()
            try:
                with self.opener(request, timeout=30) as response:
                    data = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return []
                if e.code == 429:
                    if rate_limited < self.max_retries:
                        rate_limited += 1
                        self.sleep(_retry_after(e))
                        continue
                    raise LookupUnavailable(f"Have I Been Pwned answered 429 {_HIBP_ERRORS[429]}") from e
                if e.code >= 500:
                    if transient < self.transient_retries:
                        transient += 1
                        self.sleep(self.transient_wait)
                        continue
                    raise LookupUnavailable(f"Have I Been Pwned answered {e.code} (server error)") from e
                if e.code == 400:
                    raise LookupUnavailable("Have I Been Pwned answered 400 (not a valid email address)") from e
                raise RuntimeError(f"Have I Been Pwned answered {e.code} {_HIBP_ERRORS.get(e.code, e.reason)}") from e
            except (urllib.error.URLError, TimeoutError) as e:
                if transient < self.transient_retries:
                    transient += 1
                    self.sleep(self.transient_wait)
                    continue
                raise LookupUnavailable(f"Have I Been Pwned could not be reached: {e}") from e
            return [_hibp_breach(entry) for entry in data]

    def _wait_for_rate_limit(self) -> None:
        if self._last_request is not None:
            remaining = self.min_interval - (self.clock() - self._last_request)
            if remaining > 0:
                self.sleep(remaining)
        self._last_request = self.clock()


_HIBP_ERRORS = {
    401: "(the API key is invalid)",
    403: "(no user agent or access denied)",
    429: "(rate limit still exceeded after retrying)",
}


def _hibp_breach(entry: dict) -> Breach:
    flags = set()
    if entry.get("IsSpamList"):
        flags.add(SPAM_LIST)
    if entry.get("IsFabricated"):
        flags.add(FABRICATED)
    if entry.get("IsVerified") is False:
        flags.add(UNVERIFIED)
    if entry.get("IsMalware") or entry.get("IsStealerLog"):
        flags.add(MALWARE)
    return Breach(
        name=entry["Name"],
        date=entry["BreachDate"],
        data_classes=tuple(entry.get("DataClasses", [])),
        flags=frozenset(flags),
    )


def _retry_after(error: urllib.error.HTTPError) -> float:
    try:
        return float(error.headers.get("Retry-After", 2)) + 0.5  # a little margin
    except ValueError:
        return 2.0


def get_breach_source(name: str | None = None, dataset: str | None = None) -> BreachSource:
    """The source to use: `name` and `dataset` when given (the CLI), otherwise the
    configuration in Settings: BREACH_SOURCE (default "local"), BREACH_DATASET,
    HIBP_API_KEY and HIBP_MIN_INTERVAL_SECONDS."""
    settings = None
    if name is None:
        settings = _settings()
        name, dataset = settings.breach_source, dataset or settings.breach_dataset
    name = name.lower()
    if name == "local":
        return LocalDatasetSource(dataset or DEFAULT_DATASET)
    if name == "hibp":
        if settings is None:
            # The CLI has no database configuration, so it reads the key straight from the environment
            return HibpSource(os.environ.get("HIBP_API_KEY", ""))
        return HibpSource(settings.hibp_api_key or "", min_interval=settings.hibp_min_interval_seconds)
    raise ValueError(f"Unknown breach source {name!r}; expected 'local' or 'hibp'")


def _settings():
    # Imported here, not at the top: Settings needs the database configuration, which the
    # command-line tool and the tests do not have
    from qnsentry.config import settings

    return settings
