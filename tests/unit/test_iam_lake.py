"""Opt-in CloudTrail Lake history for IAM evidence (FR-16b)."""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from posturanet.aws.readonly import ReadOnlyClient, is_allowed
from posturanet.errors import StageStop
from posturanet.iamfix.evidence import CloudTrailLake, usage, with_history
from posturanet.models import Confidence
from posturanet.models.config import Config
from posturanet.models.iam import IamEvidence, ServiceAccess, TrackedUse

TODAY = date(2026, 10, 30)


def _ev() -> IamEvidence:
    return IamEvidence(
        policy_arn="arn:aws:iam::123456789012:policy/app",
        source="iam_last_accessed",
        age_days=500,
        principals=["role/app"],
        services=[
            ServiceAccess(
                namespace="rds",
                last_accessed=date(2026, 10, 1),
                action_level=True,
                actions=[
                    TrackedUse(action="rds:DescribeDBInstances", last_seen=date(2026, 10, 1)),
                    TrackedUse(action="rds:StartExportTask", last_seen=None),
                ],
            ),
            ServiceAccess(namespace="sqs", last_accessed=None, action_level=False),
        ],
        confidence=Confidence.HIGH,
    )


def test_history_only_adds_use() -> None:
    ev = with_history(
        _ev(),
        {
            "rds:StartExportTask": date(2025, 8, 26),  # 430 days back: past IAM's tracking
            "rds:DescribeDBInstances": date(2025, 1, 1),  # older than last-accessed: no change
            "ec2:RunInstances": date(2026, 1, 1),  # not allowed by the policy: ignored
        },
    )
    use = usage(ev)
    assert use["rds"].actions == {"rds:DescribeDBInstances", "rds:StartExportTask"}
    assert not use["sqs"].accessed
    rds = ev.services[0]
    assert rds.last_accessed == date(2026, 10, 1)
    assert rds.actions[0].last_seen == date(2026, 10, 1)
    assert ev.source == "iam_last_accessed+cloudtrail_lake"
    assert with_history(_ev(), {}) == _ev()


class FakeCloudTrail:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages, self.sql = pages, ""

    def start_query(self, **kw: Any) -> dict[str, str]:
        self.sql = kw["QueryStatement"]
        return {"QueryId": "q1"}

    def get_query_results(self, **kw: Any) -> dict[str, Any]:
        return self.pages.pop(0)


def _row(source: str, name: str, last: str) -> list[dict[str, str]]:
    return [{"eventSource": source}, {"eventName": name}, {"last": last}]


def test_lake_query_reads_actions_for_the_policy_principals() -> None:
    ct = FakeCloudTrail(
        [
            {"QueryStatus": "RUNNING"},
            {
                "QueryStatus": "FINISHED",
                "QueryResultRows": [_row("rds.amazonaws.com", "StartExportTask", "2025-08-26 03:00:00.000")],
                "NextToken": "t",
            },
            {
                "QueryStatus": "FINISHED",
                "QueryResultRows": [_row("monitoring.amazonaws.com", "PutMetricData", "2026-10-01 00:00:00.000")],
            },
        ]
    )  # fmt: skip
    lake = CloudTrailLake(
        ReadOnlyClient(ct, "cloudtrail"),
        "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/eds-0123",
        sleep=lambda s: None,
    )
    seen = lake.actions(["role/app", "user/ci", "group/ops"], date(2024, 10, 30), TODAY)
    assert seen == {
        "rds:StartExportTask": date(2025, 8, 26),
        "cloudwatch:PutMetricData": date(2026, 10, 1),
    }
    assert "FROM eds-0123 " in ct.sql
    assert "sessionIssuer.userName IN ('app')" in ct.sql and "userName IN ('ci')" in ct.sql
    assert "eventTime >= '2024-10-30 00:00:00'" in ct.sql


def test_lake_refuses_names_that_could_change_the_query() -> None:
    lake = CloudTrailLake(FakeCloudTrail([]), "eds-0123", sleep=lambda s: None)
    with pytest.raises(StageStop, match="isn't valid"):
        lake.actions(["role/app') OR (1=1"], date(2024, 1, 1), TODAY)
    with pytest.raises(StageStop, match="event data store"):
        CloudTrailLake(FakeCloudTrail([]), "eds' --", sleep=lambda s: None)


def test_lake_failed_query_is_unknown() -> None:
    lake = CloudTrailLake(
        FakeCloudTrail([{"QueryStatus": "FAILED"}]), "eds-1", sleep=lambda s: None
    )
    with pytest.raises(StageStop, match="query failed") as err:
        lake.actions(["role/app"], date(2024, 1, 1), TODAY)
    assert err.value.unknown


def test_lake_is_opt_in_and_needs_a_store() -> None:
    assert Config().evidence.cloudtrail_lake.enabled is False
    with pytest.raises(ValueError, match="event_data_store"):
        Config.model_validate({"evidence": {"cloudtrail_lake": {"enabled": True}}})
    assert is_allowed("cloudtrail:StartQuery") and is_allowed("cloudtrail:GetQueryResults")
    assert not is_allowed("cloudtrail:CreateEventDataStore")
