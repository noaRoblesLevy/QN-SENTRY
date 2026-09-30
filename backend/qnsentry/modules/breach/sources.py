"""Breach sources: where the Breach module looks up email addresses (issue #11).

A source answers one question: in which known data breaches does this address appear?
It is pluggable, so the module does not change when the source does:

- LocalDatasetSource: a JSON file with fictitious breaches, for the demo and tests (#11)
- Have I Been Pwned: the real-world source, added in #13

The shape of a breach follows the Have I Been Pwned API, so both sources return the same.
Data minimisation (docs/project/05-legal-ethical.md): a source only returns the breach
name, date and the *kinds* of data exposed, never the leaked data itself.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

# The fictitious breaches of the BadSecurityInc test environment
DEFAULT_DATASET = Path(__file__).resolve().parent / "testdata" / "breaches.json"


@dataclass(frozen=True)
class Breach:
    name: str
    date: str  # YYYY-MM-DD
    data_classes: tuple[str, ...]  # kinds of data exposed, e.g. ("Email addresses", "Passwords")


class BreachSource(ABC):
    @abstractmethod
    def lookup(self, email: str) -> list[Breach]:
        """The breaches `email` appears in; [] when it appears in none."""


class LocalDatasetSource(BreachSource):
    """Breaches from a JSON file: a catalogue of breaches, and per address the breach names.

    {"breaches": {"ExampleShop": {"date": "2021-06-22", "data_classes": [...]}},
     "accounts": {"jan.peeters@badsecurityinc.be": ["ExampleShop"]}}
    """

    def __init__(self, path: Path | str = DEFAULT_DATASET):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise RuntimeError(f"Breach dataset {path} could not be read: {e}") from e

        catalogue = {
            name: Breach(name=name, date=entry["date"], data_classes=tuple(entry["data_classes"]))
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


def get_breach_source(name: str | None = None, dataset: str | None = None) -> BreachSource:
    """The source to use: `name` and `dataset` when given (the CLI), otherwise the
    configuration in Settings: BREACH_SOURCE (default "local") and BREACH_DATASET."""
    if name is None:
        settings = _settings()
        name, dataset = settings.breach_source, dataset or settings.breach_dataset
    name = name.lower()
    if name == "local":
        return LocalDatasetSource(dataset or DEFAULT_DATASET)
    if name == "hibp":
        raise RuntimeError("The Have I Been Pwned source is not available yet (issue #13); use BREACH_SOURCE=local")
    raise ValueError(f"Unknown breach source {name!r}; expected 'local' or 'hibp'")


def _settings():
    # Imported here, not at the top: Settings needs the database configuration, which the
    # command-line tool and the tests do not have
    from qnsentry.config import settings

    return settings
