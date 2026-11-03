from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from posturanet.errors import StageStop
from posturanet.evidence import FileSource, LogsInsightsSource, aggregate
from posturanet.evidence.confidence import confidence_for, coverage
from posturanet.evidence.flowlogs import FlowData, FlowRecord
from posturanet.evidence.periodicity import classify, describe
from posturanet.models import Confidence, Period

START = datetime(2026, 8, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("days", "cov", "gap", "expected"),
    [
        (89, 0.97, 6, Confidence.HIGH),
        (60, 0.95, 24, Confidence.HIGH),
        (89, 0.97, 25, Confidence.MEDIUM),  # one long gap drops high
        (59, 0.99, 0, Confidence.MEDIUM),
        (14, 0.90, 0, Confidence.MEDIUM),
        (13, 1.0, 0, Confidence.LOW),
        (90, 0.89, 0, Confidence.LOW),
    ],
)
def test_confidence_rules(days: int, cov: float, gap: int, expected: Confidence) -> None:
    assert confidence_for(days, cov, gap) is expected


def test_coverage_and_max_gap() -> None:
    end = START + timedelta(hours=10)
    active = {START + timedelta(hours=h) for h in (0, 1, 5, 6, 7, 8, 9)}
    assert coverage(START, end, active) == (0.7, 3)


def _days(*offsets: int) -> set[date]:
    return {(START + timedelta(days=o)).date() for o in offsets}


def test_periodicity() -> None:
    assert classify(_days(3), 90) is Period.ONE_OFF
    assert classify(_days(1, 40, 80), 90) is Period.RARE
    assert classify(_days(*range(70)), 90) is Period.DAILY
    assert classify(_days(*range(0, 90, 7)), 90) is Period.WEEKLY
    assert classify(_days(0, 31, 61, 92), 120) is Period.MONTHLY
    assert classify(_days(0, 3, 9, 20, 41), 90) is Period.IRREGULAR


def test_describe_peak_hour() -> None:
    hist = [0] * 24
    hist[2] = 95
    hist[3] = 5
    assert describe(Period.DAILY, hist) == "daily@02:00Z"
    hist[3] = 50
    assert describe(Period.DAILY, hist) == "daily"
    assert describe(Period.RARE, [1] + [0] * 23) == "rare"


def test_file_source_fixture(flows_path: Path) -> None:
    data = FileSource(flows_path).fetch("sg-0a91f3c2", START, START)
    obs = aggregate(data, "module.bastion.aws_security_group.this")
    assert obs.confidence is Confidence.HIGH
    assert obs.window.days == 89
    assert obs.window.max_gap_hours == 6
    by_cidr = {i.cidr: i for i in obs.items}
    assert set(by_cidr) == {
        "10.0.4.12/32",
        "10.0.4.37/32",
        "10.0.5.9/32",
        "203.0.113.7/32",
        "198.51.100.23/32",
    }
    assert by_cidr["198.51.100.23/32"].period is Period.ONE_OFF
    assert by_cidr["198.51.100.23/32"].needs_review
    assert by_cidr["203.0.113.7/32"].period is Period.DAILY
    assert all(i.proto == "tcp" and i.port == 22 for i in obs.items)


def test_no_enis_means_confidence_none() -> None:
    obs = aggregate(FlowData([], START, START + timedelta(days=90), [], set(), "x"), "a")
    assert obs.confidence is Confidence.NONE


def test_evidence_never_collapses_sources() -> None:
    recs = [
        FlowRecord(f"10.0.0.{i}/32", 22, "tcp", START + timedelta(days=d), 1)
        for i in range(1, 4)
        for d in range(80)
    ]
    data = FlowData(["eni-1"], START, START + timedelta(days=80), recs, {r.hour for r in recs}, "x")
    assert sorted(i.cidr for i in aggregate(data, "a").items) == [
        "10.0.0.1/32",
        "10.0.0.2/32",
        "10.0.0.3/32",
    ]


class FakeEc2:
    def __init__(self, enis: list[str]) -> None:
        self.enis = enis
        self.calls: list[dict[str, Any]] = []

    def describe_network_interfaces(self, **kw: Any) -> dict[str, Any]:
        self.calls.append(kw)
        return {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": e,
                    "PrivateIpAddresses": [{"PrivateIpAddress": f"10.0.1.{i + 10}"}],
                }
                for i, e in enumerate(self.enis)
            ]
        }


class FakeLogs:
    def __init__(self, rows: list[list[dict[str, str]]], statuses: list[str] | None = None) -> None:
        self.rows = rows
        self.statuses = statuses or []
        self.queries: list[dict[str, Any]] = []

    def start_query(self, **kw: Any) -> dict[str, str]:
        self.queries.append(kw)
        return {"queryId": str(len(self.queries))}

    def get_query_results(self, queryId: str) -> dict[str, Any]:  # noqa: N803 - boto3 name
        if self.statuses:
            return {"status": self.statuses.pop(0), "results": []}
        idx = (int(queryId) - 1) % len(self.rows)
        return {
            "status": "Complete",
            "results": [[{"field": k, "value": v} for k, v in r.items()] for r in self.rows[idx]],
        }


def test_logs_insights_source_scopes_to_enis() -> None:
    flow = [{"srcAddr": "10.0.4.12", "dstPort": "22", "protocol": "6", "hour": "2026-08-01 09:00:00.000", "n": "4"}]  # fmt: skip
    cov = [{"hour": "2026-08-01 09:00:00.000", "n": "9"}]
    ec2, logs = FakeEc2(["eni-b", "eni-a"]), FakeLogs([flow, cov])
    src = LogsInsightsSource(ec2, logs, "/vpc/flow", sleep=lambda s: None)
    data = src.fetch("sg-1", START, START + timedelta(days=1))
    assert ec2.calls == [{"Filters": [{"Name": "group-id", "Values": ["sg-1"]}]}]
    assert data.enis == ["eni-a", "eni-b"]
    assert 'interfaceId in ["eni-a", "eni-b"]' in logs.queries[0]["queryString"]
    query = logs.queries[0]["queryString"]
    assert 'action = "ACCEPT"' in query
    # Default flow-log format: inbound is matched by destination, never by flowDirection.
    assert 'dstAddr in ["10.0.1.10", "10.0.1.11"]' in query
    assert "flowDirection" not in query
    assert data.records == [FlowRecord("10.0.4.12/32", 22, "tcp", START + timedelta(hours=9), 4)]
    assert data.active_hours == {START + timedelta(hours=9)}


def test_logs_insights_failed_query_stops() -> None:
    src = LogsInsightsSource(FakeEc2(["eni-a"]), FakeLogs([[]], ["Running", "Failed"]), "/g", sleep=lambda s: None)  # fmt: skip
    with pytest.raises(StageStop, match="query failed"):
        src.fetch("sg-1", START, START + timedelta(days=1))


def test_logs_insights_row_cap_stops() -> None:
    row = {"srcAddr": "10.0.0.1", "dstPort": "22", "protocol": "6", "hour": "2026-08-01 00:00:00", "n": "1"}  # fmt: skip
    src = LogsInsightsSource(FakeEc2(["eni-a"]), FakeLogs([[row] * 10_000]), "/g", sleep=lambda s: None)  # fmt: skip
    with pytest.raises(StageStop, match="row limit"):
        src.fetch("sg-1", START, START + timedelta(days=1))


def test_malformed_row_stops_instead_of_dropping() -> None:
    bad = [{"srcAddr": "not-an-ip", "dstPort": "22", "protocol": "6", "hour": "2026-08-01 00:00:00", "n": "1"}]  # fmt: skip
    src = LogsInsightsSource(FakeEc2(["eni-a"]), FakeLogs([bad]), "/g", sleep=lambda s: None)
    with pytest.raises(StageStop, match="unexpected flow-log row"):
        src.fetch("sg-1", START, START + timedelta(days=1))


def test_no_enis_skips_queries() -> None:
    logs = FakeLogs([[]])
    data = LogsInsightsSource(FakeEc2([]), logs, "/g").fetch("sg-1", START, START)
    assert data.enis == [] and logs.queries == []
