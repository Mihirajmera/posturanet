"""Read-only AWS access (NFR-2, architecture doc 7.3).

Every AWS call in PosturaNet goes through `ReadOnlyClient`. Operations not on the allowlist
raise `MutatingCallBlocked` before anything reaches the network. The generated IAM policy
(`iam_policy()`) is built from the same list so the two can't drift apart.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from posturanet.errors import PosturaNetError

ALLOWLIST: tuple[str, ...] = (
    "ec2:Describe*",
    "logs:StartQuery",
    "logs:GetQueryResults",
    "logs:DescribeLogGroups",
    "athena:StartQueryExecution",
    "athena:GetQueryExecution",
    "athena:GetQueryResults",
    "s3:GetObject",
    "s3:ListBucket",
    # S3 public-access evidence (FR-50): bucket exposure, access logs, CloudFront origins.
    "s3:ListAllMyBuckets",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketAcl",
    "s3:GetBucketOwnershipControls",
    "s3:GetBucketWebsite",
    "s3:GetBucketLogging",
    "cloudfront:ListDistributions",
    # IAM fix verification (FR-32): AccessDenied on removed actions.
    "cloudtrail:LookupEvents",
    "iam:Get*",
    "iam:List*",
    "iam:GenerateServiceLastAccessedDetails",
    "iam:SimulatePrincipalPolicy",
    "securityhub:GetFindings",
    # Remediation plans (FR-4c): the plans, their exposures, and those exposure findings.
    "securityhub:GetFindingsV2",
    "securityhub:GetRemediationsV2",
    "securityhub:ListExposuresByRemediationV2",
    "access-analyzer:Get*",
    "access-analyzer:List*",
    "sts:GetCallerIdentity",
    "sts:AssumeRole",
)

# boto3 service names that differ from IAM action prefixes.
_IAM_PREFIX = {"accessanalyzer": "access-analyzer"}
# boto3 methods whose IAM action isn't the CamelCase of the method name.
_IAM_ACTION = {
    ("s3", "list_buckets"): "s3:ListAllMyBuckets",
    ("s3", "list_objects_v2"): "s3:ListBucket",
}


class MutatingCallBlocked(PosturaNetError):
    """An AWS operation outside the read-only allowlist was attempted."""

    exit_code = 10


def iam_action(service: str, method: str) -> str:
    """`("ec2", "describe_network_interfaces")` -> `"ec2:DescribeNetworkInterfaces"`."""
    if (service, method) in _IAM_ACTION:
        return _IAM_ACTION[(service, method)]
    prefix = _IAM_PREFIX.get(service, service)
    op = "".join(part.capitalize() for part in method.split("_"))
    return f"{prefix}:{op}"


def is_allowed(action: str) -> bool:
    return any(fnmatch.fnmatchcase(action, pattern) for pattern in ALLOWLIST)


_PAGINATOR = re.compile(r"^(get_paginator|can_paginate|get_waiter)$")


class ReadOnlyClient:
    """Wraps a boto3 client; only allowlisted operations are reachable."""

    def __init__(self, client: Any, service: str) -> None:
        self._client = client
        self._service = service

    @property
    def service(self) -> str:
        return self._service

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or _PAGINATOR.match(name):
            # Paginators and waiters would bypass the per-call check.
            raise MutatingCallBlocked(f"{self._service}.{name} is not available in PosturaNet")
        action = iam_action(self._service, name)
        if not is_allowed(action):
            raise MutatingCallBlocked(
                f"{action} is not on the read-only allowlist; PosturaNet never writes to AWS"
            )
        return getattr(self._client, name)


def iam_policy() -> dict[str, Any]:
    """IAM policy document a customer attaches to PosturaNet's role."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PosturaNetReadOnly",
                "Effect": "Allow",
                "Action": sorted(ALLOWLIST),
                "Resource": "*",
            }
        ],
    }
