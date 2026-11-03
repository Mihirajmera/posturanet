"""Classify how often a source is seen (architecture doc 6.3)."""

from __future__ import annotations

from datetime import date

from posturanet.models import Period

NEEDS_REVIEW = frozenset({Period.RARE, Period.ONE_OFF})


def classify(days_seen: set[date], window_days: int) -> Period:
    n = len(days_seen)
    if n <= 1:
        return Period.ONE_OFF
    if n <= 3:
        return Period.RARE
    if window_days > 0 and n >= 0.7 * window_days:
        return Period.DAILY
    if len({d.weekday() for d in days_seen}) == 1:
        return Period.WEEKLY
    if len({d.day for d in days_seen}) == 1:
        return Period.MONTHLY
    return Period.IRREGULAR


def peak_hour(histogram: list[int]) -> int | None:
    """The UTC hour holding at least 90% of connections, if there is one."""
    total = sum(histogram)
    if total == 0:
        return None
    hour = max(range(24), key=lambda h: histogram[h])
    return hour if histogram[hour] >= 0.9 * total else None


def describe(period: Period, histogram: list[int]) -> str:
    """Human and contract form: `daily`, `daily@02:00Z`, `rare`…"""
    hour = peak_hour(histogram)
    if hour is not None and period in (Period.DAILY, Period.WEEKLY, Period.MONTHLY):
        return f"{period.value}@{hour:02d}:00Z"
    return period.value
