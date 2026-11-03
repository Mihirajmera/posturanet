"""Evidence stage: Location -> Observations (FR-11..FR-15)."""

from __future__ import annotations

from datetime import datetime, timedelta

from posturanet.evidence.flowlogs import FileSource, FlowSource, LogsInsightsSource, aggregate
from posturanet.models import Observations


def collect(
    source: FlowSource,
    group_id: str,
    resource_address: str,
    *,
    now: datetime,
    window_days: int,
) -> Observations:
    end = now.replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=window_days)
    data = source.fetch(group_id, start, end)
    return aggregate(data, resource_address)


__all__ = ["FileSource", "FlowSource", "LogsInsightsSource", "aggregate", "collect"]
