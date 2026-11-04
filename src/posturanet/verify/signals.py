"""Post-merge signals: flow-log REJECTs from contracted sources, Security Hub status (FR-31, FR-32).

Read-only. REJECT rows come from the same Logs Insights path as the evidence collector, or
from a JSON file for offline runs and tests.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from posturanet.errors import StageStop
from posturanet.evidence.flowlogs import (
    _CHUNK,
    FlowRecord,
    LogsInsightsSource,
    _proto,
    _single,
    parse_ts,
)

_REJECT_QUERY = (
    "fields srcAddr, dstAddr, dstPort, protocol, action, @timestamp"
    ' | filter interfaceId in [{enis}] and action = "REJECT" and dstAddr in [{ips}]'
    " | stats count(*) as n by srcAddr, dstPort, protocol, datefloor(@timestamp, 1h) as hour"
)


class RejectSource(Protocol):
    def rejects(self, group_id: str, start: datetime, end: datetime) -> list[FlowRecord]: ...


class RejectFile:
    """`{"records": [{"srcAddr", "dstPort", "protocol", "hour", "n"}]}`: inbound REJECTs."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def rejects(self, group_id: str, start: datetime, end: datetime) -> list[FlowRecord]:
        try:
            raw: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
            rows = [
                FlowRecord(
                    src=_single(r["srcAddr"]),
                    port=int(r["dstPort"]),
                    proto=_proto(r["protocol"]),
                    hour=parse_ts(r["hour"]),
                    count=int(r.get("n", 1)),
                )
                for r in raw.get("records", [])
            ]
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise StageStop("watch", f"cannot read rejects file {self.path}: {exc}") from exc
        return [r for r in rows if start <= r.hour < end]


class LogsInsightsRejects(LogsInsightsSource):
    def rejects(self, group_id: str, start: datetime, end: datetime) -> list[FlowRecord]:
        enis, ips = self._interfaces(group_id)
        if not enis or not ips:
            raise StageStop(
                "watch",
                "the security group has no network interfaces to watch",
                ["check the group is still attached, then re-run"],
            )
        eni_list = ", ".join(json.dumps(e) for e in enis)
        ip_list = ", ".join(json.dumps(ip) for ip in ips)
        out: list[FlowRecord] = []
        cur = start
        while cur < end:
            nxt = min(cur + _CHUNK, end)
            for row in self._query(_REJECT_QUERY.format(enis=eni_list, ips=ip_list), cur, nxt):
                try:
                    out.append(
                        FlowRecord(
                            src=_single(row["srcAddr"]),
                            port=int(row["dstPort"]),
                            proto=_proto(row["protocol"]),
                            hour=parse_ts(row["hour"]),
                            count=int(row.get("n", "1")),
                        )
                    )
                except (KeyError, ValueError) as exc:
                    raise StageStop(
                        "watch", f"unexpected flow-log row ({exc.__class__.__name__})"
                    ) from exc
            cur = nxt
        return out


def finding_status(securityhub: Any, finding_id: str) -> tuple[str, datetime | None] | None:
    """(compliance status, last updated) of the finding in Security Hub, or None if gone."""
    resp = securityhub.get_findings(
        Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]}, MaxResults=1
    )
    items = resp.get("Findings") or []
    if not items:
        return None
    item = items[0]
    status = str((item.get("Compliance") or {}).get("Status", "UNKNOWN"))
    if item.get("RecordState") == "ARCHIVED":
        status = "ARCHIVED"
    updated = item.get("UpdatedAt")
    return status, parse_ts(str(updated)) if updated else None


def window_end(start: datetime, hours: int) -> datetime:
    return start + timedelta(hours=hours)
