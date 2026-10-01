"""Risk score: one number from 0 to 100 per scan and per client (issue #19).

The method is described in the data contract (docs/project/10-data-contract.md, 10.7)
and was agreed in the review of #53. The weights, scale and floors are here, in one
place, so they are easy to change.

1. Every finding adds points by severity (WEIGHTS)
2. curve = 100 * (1 - e^(-points / SCALE))
3. score = the curve, but at least the floor of the worst finding (FLOORS)

The curve gives diminishing returns: the first serious findings raise the score the
most, it never exceeds 100, and adding a finding never lowers it. A plain sum would
reach 100 after a few findings; an average would drop when harmless findings are added.

The floor keeps the level honest for a single serious finding: with the curve alone one
critical finding scores 39 ("moderate"), while critical means "fix immediately".
"""

import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
SCALE = 50
# The score is at least the floor of the worst finding: its level then matches its severity
FLOORS = {"critical": 75, "high": 50, "medium": 25, "low": 0, "info": 0}
# (lowest score, level), highest first
LEVELS = [(75, "very_high"), (50, "high"), (25, "moderate"), (0, "low")]


@dataclass(frozen=True)
class Risk:
    score: int  # 0 to 100
    level: str  # low, moderate, high, very_high
    points: int
    # False when the scan ended "partial": a module failed, so findings may be missing
    complete: bool = True


def compute_risk(severities: Iterable[str], *, complete: bool = True) -> Risk:
    counts = Counter(str(s) for s in severities)
    points = sum(WEIGHTS.get(severity, 0) * count for severity, count in counts.items())
    curve = round(100 * (1 - math.exp(-points / SCALE)))
    floor = max((FLOORS.get(severity, 0) for severity in counts), default=0)
    score = max(curve, floor)
    return Risk(score=score, level=level_of(score), points=points, complete=complete)


def level_of(score: int) -> str:
    return next(level for lowest, level in LEVELS if score >= lowest)
