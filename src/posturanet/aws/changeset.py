"""Opt-in CloudFormation change-set preview (FR-10a, the one NFR-2 exception).

Kept apart from `readonly.py` on purpose: its own action list, its own role and its own IAM
policy. `ChangeSetClient` exposes named methods only (no pass-through), always creates an
UPDATE change set on an existing stack, and has no way to execute one. The generated policy
denies `ExecuteChangeSet` and every stack write. See docs/design/cfn-changeset-preview.md.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from posturanet.aws.readonly import MutatingCallBlocked, iam_action

CHANGESET_ACTIONS: tuple[str, ...] = (
    "cloudformation:CreateChangeSet",
    "cloudformation:DescribeChangeSet",
    "cloudformation:DeleteChangeSet",
    "cloudformation:DescribeStacks",  # current parameters and capabilities
    "cloudformation:ListChangeSets",  # sweep of leftovers from earlier runs
)

DENIED_ACTIONS: tuple[str, ...] = (
    "cloudformation:ExecuteChangeSet",
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
    "cloudformation:DeleteStack",
    "cloudformation:RollbackStack",
    "cloudformation:ContinueUpdateRollback",
    "cloudformation:CancelUpdateStack",
    "iam:PassRole",
)

NAME_PREFIX = "posturanet-"


class ChangeSetClient:
    """Create, describe and delete PosturaNet's own change sets. Nothing else."""

    def __init__(
        self,
        client: Callable[[], Any],  # lazy: credentials resolve on first use
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client
        self.clock = clock
        self.sleep = sleep

    def _call(self, method: str, **kw: Any) -> Any:
        action = iam_action("cloudformation", method)
        if action not in CHANGESET_ACTIONS:
            raise MutatingCallBlocked(f"{action} is not allowed in the change-set preview")
        return getattr(self._client(), method)(**kw)

    def describe_stack(self, stack: str) -> dict[str, Any]:
        stacks: list[dict[str, Any]] = self._call("describe_stacks", StackName=stack)["Stacks"]
        return stacks[0]

    def list_change_sets(self, stack: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        kw: dict[str, Any] = {"StackName": stack}
        while True:
            page = self._call("list_change_sets", **kw)
            out += page.get("Summaries", [])
            if not page.get("NextToken"):
                return out
            kw["NextToken"] = page["NextToken"]

    def create(
        self,
        stack: str,
        name: str,
        body: str,
        parameters: list[str],
        capabilities: list[str],
    ) -> None:
        if not name.startswith(NAME_PREFIX):
            raise ValueError(f"change-set names start with {NAME_PREFIX}")
        kw: dict[str, Any] = {
            "StackName": stack,
            "ChangeSetName": name,
            "ChangeSetType": "UPDATE",  # never CREATE: that leaves a REVIEW_IN_PROGRESS stack
            "TemplateBody": body,
            "Parameters": [{"ParameterKey": p, "UsePreviousValue": True} for p in parameters],
            "Description": "PosturaNet preview. Do not execute; it is deleted after validation.",
        }
        if capabilities:
            kw["Capabilities"] = capabilities
        self._call("create_change_set", **kw)

    def describe(self, stack: str, name: str) -> dict[str, Any]:
        kw: dict[str, Any] = {"StackName": stack, "ChangeSetName": name}
        page: dict[str, Any] = self._call("describe_change_set", **kw)
        changes = list(page.get("Changes", []))
        while page.get("NextToken"):
            page = self._call("describe_change_set", **kw, NextToken=page["NextToken"])
            changes += page.get("Changes", [])
        return {**page, "Changes": changes}

    def delete(self, stack: str, name: str) -> None:
        if not name.startswith(NAME_PREFIX):
            raise ValueError(f"PosturaNet only deletes its own change sets ({NAME_PREFIX}*)")
        self._call("delete_change_set", StackName=stack, ChangeSetName=name)


def changeset_policy() -> dict[str, Any]:
    """IAM policy for the separate preview role. Attach it only if you opt in."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PosturaNetChangeSetCreate",
                "Effect": "Allow",
                "Action": ["cloudformation:CreateChangeSet"],
                "Resource": "arn:aws:cloudformation:*:*:stack/*/*",
                "Condition": {"StringLike": {"cloudformation:ChangeSetName": f"{NAME_PREFIX}*"}},
            },
            {
                "Sid": "PosturaNetChangeSetReadDelete",
                "Effect": "Allow",
                "Action": sorted(set(CHANGESET_ACTIONS) - {"cloudformation:CreateChangeSet"}),
                "Resource": "arn:aws:cloudformation:*:*:stack/*/*",
            },
            {
                "Sid": "PosturaNetNeverExecutes",
                "Effect": "Deny",
                "Action": sorted(DENIED_ACTIONS),
                "Resource": "*",
            },
        ],
    }
