"""VPC flow-log evidence for security groups (FR-11, architecture doc 7.1).

Two sources produce the same `FlowRecord` rows:
- `LogsInsightsSource` queries CloudWatch Logs Insights through the read-only client.
- `FileSource` reads a JSON export (`--evidence-file`), for offline runs and tests.

Aggregation into `Observations` is pure. Source IPs are never collapsed here (7.1 step 4).
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from posturanet.errors import StageStop
from posturanet.evidence.confidence import confidence_for, coverage, hours_in
from posturanet.evidence.periodicity import NEEDS_REVIEW, classify
from posturanet.models import Confidence, Observations, ObservedFlow, Window

PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}

_MAX_ROWS = 10_000  # Logs Insights result cap; hitting it means the answer may be partial
_CHUNK = timedelta(days=7)


@dataclass(frozen=True)
class FlowRecord:
    src: str
    port: int
    proto: str
    hour: datetime
    count: int


@dataclass
class FlowData:
    enis: list[str]
    start: datetime
    end: datetime
    records: list[FlowRecord]
    active_hours: set[datetime]  # hours with any record for the ENIs (coverage)
    source: str
    notes: list[str] = field(default_factory=list)


class FlowSource(Protocol):
    def fetch(self, group_id: str, start: datetime, end: datetime) -> FlowData: ...


def parse_ts(value: str) -> datetime:
    text = value.strip().replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _proto(value: str) -> str:
    return PROTOCOLS.get(str(value).strip(), str(value).strip().lower())


def _single(addr: str) -> str:
    ip = ipaddress.ip_address(addr.strip())
    return f"{ip}/{ip.max_prefixlen}"


def aggregate(data: FlowData, resource_address: str) -> Observations:
    window_days = max(1, round((data.end - data.start).total_seconds() / 86400))
    ratio, max_gap = coverage(data.start, data.end, data.active_hours)

    per_key: dict[tuple[str, int, str], list[FlowRecord]] = defaultdict(list)
    for rec in data.records:
        if data.start <= rec.hour < data.end:
            per_key[(rec.src, rec.port, rec.proto)].append(rec)

    items: list[ObservedFlow] = []
    for (src, port, proto), recs in sorted(per_key.items()):
        hist = [0] * 24
        days: set[date] = set()
        for r in recs:
            hist[r.hour.hour] += r.count
            days.add(r.hour.date())
        period = classify(days, window_days)
        items.append(
            ObservedFlow(
                cidr=src,
                port=port,
                proto=proto,
                count=sum(r.count for r in recs),
                first_seen=min(r.hour for r in recs),
                last_seen=max(r.hour for r in recs) + timedelta(hours=1),
                days_seen=len(days),
                period=period,
                needs_review=period in NEEDS_REVIEW,
                hours_histogram=hist,
            )
        )

    if not data.enis or not data.active_hours:
        conf = Confidence.NONE
    else:
        conf = confidence_for(window_days, ratio, max_gap)
    return Observations(
        resource_address=resource_address,
        source=data.source,
        enis=sorted(data.enis),
        window=Window(
            start=data.start,
            end=data.end,
            days=window_days,
            coverage_ratio=ratio,
            max_gap_hours=max_gap,
        ),
        items=items,
        confidence=conf,
    )


# --- file source ---------------------------------------------------------------------------


class FileSource:
    """JSON export:
    `{"enis": [...], "window": {"from", "to"}, "missing_hours": [...]?,
      "records": [{"srcAddr", "dstPort", "protocol", "hour", "n"}]}`

    Without `missing_hours`, coverage is computed from the record hours only (conservative).
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def fetch(self, group_id: str, start: datetime, end: datetime) -> FlowData:
        try:
            raw: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StageStop("evidence", f"cannot read evidence file {self.path}: {exc}") from exc
        try:
            w_start = parse_ts(raw["window"]["from"])
            w_end = parse_ts(raw["window"]["to"])
            records = [
                FlowRecord(
                    src=_single(r["srcAddr"]),
                    port=int(r["dstPort"]),
                    proto=_proto(r["protocol"]),
                    hour=parse_ts(r["hour"]),
                    count=int(r.get("n", 1)),
                )
                for r in raw.get("records", [])
            ]
            enis = [str(e) for e in raw.get("enis", [])]
        except (KeyError, TypeError, ValueError) as exc:
            raise StageStop("evidence", f"evidence file {self.path} is malformed: {exc}") from exc

        if "missing_hours" in raw:
            missing = {parse_ts(h) for h in raw["missing_hours"]}
            active = {h for h in hours_in(w_start, w_end) if h not in missing}
        else:
            active = {r.hour for r in records}
        return FlowData(
            enis=enis,
            start=w_start,
            end=w_end,
            records=records,
            active_hours=active,
            source="flow_logs_file",
        )


# --- CloudWatch Logs Insights source -------------------------------------------------------

# Inbound = addressed to one of the interfaces' own IPs. `flowDirection` is not used: it only
# exists in custom log formats, and Logs Insights auto-parses only the default format. Filtering
# on it would silently return zero inbound flows and make every rule look unused.
_FLOW_QUERY = (
    "fields srcAddr, dstAddr, dstPort, protocol, action, @timestamp"
    ' | filter interfaceId in [{enis}] and action = "ACCEPT" and dstAddr in [{ips}]'
    " | stats count(*) as n by srcAddr, dstPort, protocol, datefloor(@timestamp, 1h) as hour"
)
_COVERAGE_QUERY = (
    "filter interfaceId in [{enis}] | stats count(*) as n by datefloor(@timestamp, 1h) as hour"
)


class LogsInsightsSource:
    def __init__(
        self,
        ec2: Any,
        logs: Any,
        log_group: str,
        *,
        sleep: Callable[[float], None] = time.sleep,
        poll_s: float = 1.0,
        timeout_s: float = 300.0,
    ) -> None:
        self.ec2 = ec2
        self.logs = logs
        self.log_group = log_group
        self.sleep = sleep
        self.poll_s = poll_s
        self.timeout_s = timeout_s

    def fetch(self, group_id: str, start: datetime, end: datetime) -> FlowData:
        enis, ips = self._interfaces(group_id)
        if not enis:
            return FlowData([], start, end, [], set(), "vpc_flow_logs")
        if not ips:
            raise StageStop(
                "evidence",
                "the security group's network interfaces have no IP addresses to match",
                ["check the interfaces with `aws ec2 describe-network-interfaces`"],
            )
        eni_list = ", ".join(json.dumps(e) for e in enis)
        ip_list = ", ".join(json.dumps(ip) for ip in ips)

        records: list[FlowRecord] = []
        active: set[datetime] = set()
        cur = start
        while cur < end:
            nxt = min(cur + _CHUNK, end)
            for row in self._query(_FLOW_QUERY.format(enis=eni_list, ips=ip_list), cur, nxt):
                try:
                    records.append(
                        FlowRecord(
                            src=_single(row["srcAddr"]),
                            port=int(row["dstPort"]),
                            proto=_proto(row["protocol"]),
                            hour=parse_ts(row["hour"]),
                            count=int(row.get("n", "1")),
                        )
                    )
                except (KeyError, ValueError) as exc:
                    # Dropping a row would under-count real traffic; never guess.
                    raise StageStop(
                        "evidence",
                        f"unexpected flow-log row from Logs Insights ({exc.__class__.__name__})",
                        ["PosturaNet R1 reads the default VPC flow-log format"],
                    ) from exc
            for row in self._query(_COVERAGE_QUERY.format(enis=eni_list), cur, nxt):
                if "hour" in row:
                    active.add(parse_ts(row["hour"]))
            cur = nxt
        return FlowData(enis, start, end, records, active, "vpc_flow_logs")

    def _interfaces(self, group_id: str) -> tuple[list[str], list[str]]:
        """(ENI ids, their private IPv4 and IPv6 addresses) for the security group."""
        resp = self.ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [group_id]}]
        )
        enis: list[str] = []
        ips: set[str] = set()
        for ni in resp.get("NetworkInterfaces", []):
            enis.append(ni["NetworkInterfaceId"])
            ips.update(a["PrivateIpAddress"] for a in ni.get("PrivateIpAddresses", []))
            ips.update(a["Ipv6Address"] for a in ni.get("Ipv6Addresses", []))
        return sorted(enis), sorted(ips)

    def _query(self, query: str, start: datetime, end: datetime) -> list[dict[str, str]]:
        qid = self.logs.start_query(
            logGroupName=self.log_group,
            startTime=int(start.timestamp()),
            endTime=int(end.timestamp()),
            queryString=query,
            limit=_MAX_ROWS,
        )["queryId"]
        waited = 0.0
        while True:
            resp = self.logs.get_query_results(queryId=qid)
            status = resp.get("status")
            if status == "Complete":
                break
            if status in ("Failed", "Cancelled", "Timeout", "Unknown"):
                raise StageStop(
                    "evidence",
                    f"Logs Insights query {status.lower()} on {self.log_group}",
                    ["check the log group name and that flow logs are delivered there"],
                )
            if waited >= self.timeout_s:
                raise StageStop("evidence", "Logs Insights query timed out")
            self.sleep(self.poll_s)
            waited += self.poll_s
        rows = [{f["field"]: f["value"] for f in r} for r in resp.get("results", [])]
        if len(rows) >= _MAX_ROWS:
            raise StageStop(
                "evidence",
                f"flow-log query hit the {_MAX_ROWS:,}-row limit; results may be partial",
                ["Athena mode for high-volume groups arrives in a later release"],
            )
        return rows
