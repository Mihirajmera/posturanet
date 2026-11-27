"""How long `posturanet verify` watches after a fix: long enough for the least frequent kept user.

A fixed 72 hours misses a weekly or monthly job: it first runs, and is denied, after the watch
has already said CONFIRMED. The window is the expected gap of the least frequent kept source
(security groups, from flow-log periodicity) or the longest gap since a kept action was last
used (IAM), between 72 hours and 35 days. Anything rarer than 35 days stays a residual risk in
the PR, as before.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date

from posturanet.models.observations import Period

MIN_HOURS = 72
MAX_HOURS = 35 * 24

_PERIOD_HOURS = {
    Period.DAILY: MIN_HOURS,
    Period.WEEKLY: 8 * 24,  # a week plus a day of slack
    Period.MONTHLY: MAX_HOURS,
    Period.IRREGULAR: MAX_HOURS,
    Period.RARE: MAX_HOURS,
    Period.ONE_OFF: MIN_HOURS,  # not expected to come back; nothing to wait for
}


def _clamp(hours: int) -> int:
    return max(MIN_HOURS, min(MAX_HOURS, hours))


def sg_hours(periods: Iterable[Period]) -> int:
    """Watch for the least frequent kept source of a security group."""
    return max((_PERIOD_HOURS.get(p, MIN_HOURS) for p in periods), default=MIN_HOURS)


def iam_hours(last_seen: Iterable[date | None]) -> int:
    """Watch for the longest gap between the newest and the oldest use of a kept action."""
    seen = [d for d in last_seen if d is not None]
    if not seen:
        return MIN_HOURS
    gap_days = (max(seen) - min(seen)).days + 1
    return _clamp(gap_days * 24)


def label(hours: int) -> str:
    """`72h`, or `8 days` once it is a whole number of days past three."""
    return f"{hours // 24} days" if hours > MIN_HOURS and hours % 24 == 0 else f"{hours}h"
