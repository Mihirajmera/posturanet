"""NFR-2: PosturaNet never makes a mutating AWS call."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from posturanet.aws.readonly import (
    ALLOWLIST,
    MutatingCallBlocked,
    ReadOnlyClient,
    iam_action,
    iam_policy,
    is_allowed,
)
from posturanet.evidence import LogsInsightsSource
from posturanet.locate.backend import boto3_s3_fetch

SRC = Path(__file__).resolve().parents[2] / "src" / "posturanet"


class Recorder:
    """Stands in for any boto3 client; records every operation the code reaches."""

    def __init__(self, service: str, calls: list[str]) -> None:
        self.service = service
        self.calls = calls

    def __getattr__(self, name: str) -> Any:
        def op(**kw: Any) -> Any:
            self.calls.append(iam_action(self.service, name))
            if name == "describe_network_interfaces":
                return {
                    "NetworkInterfaces": [
                        {
                            "NetworkInterfaceId": "eni-1",
                            "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.1.10"}],
                        }
                    ]
                }
            if name == "start_query":
                return {"queryId": "q"}
            if name == "get_query_results":
                return {"status": "Complete", "results": []}
            if name == "get_object":

                class Body:
                    def read(self) -> bytes:
                        return b"{}"

                return {"Body": Body()}
            return {}

        return op


def test_iam_action_names() -> None:
    assert iam_action("ec2", "describe_network_interfaces") == "ec2:DescribeNetworkInterfaces"
    assert iam_action("accessanalyzer", "list_findings") == "access-analyzer:ListFindings"


@pytest.mark.parametrize(
    ("service", "method"),
    [
        ("ec2", "authorize_security_group_ingress"),
        ("ec2", "revoke_security_group_ingress"),
        ("ec2", "modify_instance_attribute"),
        ("s3", "put_object"),
        ("s3", "delete_object"),
        ("iam", "put_role_policy"),
        ("logs", "delete_log_group"),
        ("ec2", "get_paginator"),
    ],
)
def test_mutating_calls_blocked(service: str, method: str) -> None:
    client = ReadOnlyClient(Recorder(service, []), service)
    with pytest.raises(MutatingCallBlocked):
        getattr(client, method)


def test_allowlisted_calls_pass_through() -> None:
    calls: list[str] = []
    client = ReadOnlyClient(Recorder("ec2", calls), "ec2")
    client.describe_security_groups(GroupIds=["sg-1"])
    assert calls == ["ec2:DescribeSecurityGroups"]


def test_iam_policy_matches_allowlist() -> None:
    actions = iam_policy()["Statement"][0]["Action"]
    assert sorted(actions) == sorted(ALLOWLIST)
    assert not any(
        a.split(":")[1].startswith(("Put", "Delete", "Create", "Update")) for a in actions
    )


def test_collectors_only_make_allowlisted_calls() -> None:
    calls: list[str] = []

    def factory(service: str) -> ReadOnlyClient:
        return ReadOnlyClient(Recorder(service, calls), service)

    start = datetime(2026, 8, 1, tzinfo=UTC)
    LogsInsightsSource(factory("ec2"), factory("logs"), "/g", sleep=lambda s: None).fetch(
        "sg-1", start, start + timedelta(days=8)
    )
    boto3_s3_fetch(factory)("bucket", "key", None)
    assert calls, "collectors made no calls"
    assert all(is_allowed(c) for c in calls), calls


def test_no_boto3_client_outside_aws_package() -> None:
    """Every AWS client is created in aws/session.py and wrapped in ReadOnlyClient."""
    offenders = []
    for py in SRC.rglob("*.py"):
        if py.parent.name == "aws":
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = [a.name for a in node.names]
                mod = getattr(node, "module", None) or ""
                if "boto3" in names or mod.startswith(("boto3", "botocore")):
                    offenders.append(str(py.relative_to(SRC)))
    assert offenders == []
