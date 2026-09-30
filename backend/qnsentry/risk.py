"""Risk score: one number from 0 to 100 per scan and per client (issue #19).

The method is described in the data contract (docs/project/10-data-contract.md, 10.7).
It is a proposal from Noa, to be agreed in review: the weights and scale are here, in
one place, so they are easy to change.

1. Every finding adds points by severity (WEIGHTS)
2. score = 100 * (1 - e^(-points / SCALE))

The second step gives diminishing returns: the first serious findings raise the score
the most, it never exceeds 100, and adding a finding never lowers it. A plain sum would
reach 100 after a few findings; an average would drop when harmless findings are added.
"""

import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

METHOD_VERSION = 1
WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
SCALE = 50
# (lowest score, level), highest first
LEVELS = [(75, "very_high"), (50, "high"), (25, "moderate"), (0, "low")]


@dataclass(frozen=True)
class Risk:
    score: int  # 0 to 100
    level: str  # low, moderate, high, very_high
    points: int


def compute_risk(severities: Iterable[str]) -> Risk:
    counts = Counter(str(s) for s in severities)
    points = sum(WEIGHTS.get(severity, 0) * count for severity, count in counts.items())
    score = round(100 * (1 - math.exp(-points / SCALE)))
    return Risk(score=score, level=level_of(score), points=points)


def level_of(score: int) -> str:
    return next(level for lowest, level in LEVELS if score >= lowest)
