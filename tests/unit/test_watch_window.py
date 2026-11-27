"""The post-merge watch lasts long enough for the least frequent kept user (evidence/watch.py)."""

from __future__ import annotations

from datetime import date

from posturanet.evidence import watch
from posturanet.models.observations import Period


def test_sg_window_follows_the_rarest_kept_source() -> None:
    assert watch.sg_hours([]) == 72
    assert watch.sg_hours([Period.DAILY, Period.DAILY]) == 72
    assert watch.sg_hours([Period.DAILY, Period.WEEKLY]) == 8 * 24
    assert watch.sg_hours([Period.WEEKLY, Period.MONTHLY]) == 35 * 24
    assert watch.sg_hours([Period.RARE]) == 35 * 24  # capped: rarer is residual risk
    assert watch.sg_hours([Period.ONE_OFF]) == 72


def test_iam_window_follows_the_longest_gap() -> None:
    assert watch.iam_hours([]) == 72
    assert watch.iam_hours([None, date(2026, 10, 1)]) == 72
    assert watch.iam_hours([date(2026, 10, 30), date(2026, 10, 10)]) == 21 * 24
    assert watch.iam_hours([date(2026, 10, 30), date(2025, 1, 1)]) == 35 * 24


def test_label() -> None:
    assert watch.label(72) == "72h"
    assert watch.label(8 * 24) == "8 days"
