"""Evidence confidence (FR-12, architecture doc 6.3)."""

from __future__ import annotations

from datetime import datetime, timedelta

from posturanet.models import Confidence

_RANK = {Confidence.NONE: 0, Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}


def confidence_for(days: int, coverage_ratio: float, max_gap_hours: int) -> Confidence:
    if days >= 60 and coverage_ratio >= 0.95 and max_gap_hours <= 24:
        return Confidence.HIGH
    if days >= 14 and coverage_ratio >= 0.90:
        return Confidence.MEDIUM
    return Confidence.LOW


def at_least(value: Confidence, minimum: Confidence) -> bool:
    return _RANK[value] >= _RANK[minimum]


def hours_in(start: datetime, end: datetime) -> list[datetime]:
    """Every whole UTC hour in [start, end)."""
    cur = start.replace(minute=0, second=0, microsecond=0)
    out: list[datetime] = []
    while cur < end:
        out.append(cur)
        cur += timedelta(hours=1)
    return out


def coverage(start: datetime, end: datetime, active: set[datetime]) -> tuple[float, int]:
    """(coverage_ratio, max_gap_hours) of `active` hours over the window."""
    hours = hours_in(start, end)
    if not hours:
        return 0.0, 0
    present = 0
    gap = max_gap = 0
    for h in hours:
        if h in active:
            present += 1
            gap = 0
        else:
            gap += 1
            max_gap = max(max_gap, gap)
    return round(present / len(hours), 4), max_gap
