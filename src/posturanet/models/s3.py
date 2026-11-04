"""S3 public-access evidence and contract (FR-50, architecture doc 14.2)."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from posturanet.models.common import Confidence
from posturanet.models.contract import CONTRACT_SCHEMA, ObservedMeta

RequesterKind = Literal["anonymous", "cross_account", "in_account", "service", "unknown"]


class Exposure(BaseModel):
    """How a bucket can be reached publicly today, before any fix."""

    model_config = ConfigDict(extra="forbid")

    policy_public: bool
    acl_public: bool
    acls_enabled: bool  # object ownership isn't BucketOwnerEnforced: object ACLs may be public
    website: bool

    @property
    def public(self) -> bool:
        return self.policy_public or self.acl_public

    @property
    def needs_logs(self) -> bool:
        """Only a bucket that might be public needs access logs to show the fix breaks nothing."""
        return self.public or self.acls_enabled


class S3Use(BaseModel):
    """One requester seen in the access logs, aggregated over the window."""

    model_config = ConfigDict(extra="forbid")

    requester: str  # "-" for anonymous; an ARN, a canonical id, or "svc:<service>"
    kind: RequesterKind
    operations: list[str] = Field(default_factory=list)
    count: int
    last_seen: date
    owner: str | None = None
    ref: str | None = None


class CloudFrontOrigin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    distribution: str
    domain: str
    private: bool  # origin access control or identity: keeps working after the fix


class BucketEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bucket: str
    exposure: Exposure
    logging: bool
    breaks: list[S3Use] = Field(default_factory=list)  # would stop working after the fix
    keeps: list[S3Use] = Field(default_factory=list)  # keeps working (in-account, services)
    needs_review: list[S3Use] = Field(default_factory=list)  # requester not identifiable
    cloudfront: list[CloudFrontOrigin] = Field(default_factory=list)


class S3Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: Literal["bucket", "account"]
    source: str  # "s3_access_logs", "s3_evidence_file" or "s3_config"
    basis: str  # one line: why the fix does or doesn't change current access
    window_days: int
    coverage_ratio: float
    buckets: list[BucketEvidence] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)  # each one stops the fix
    confidence: Confidence


class S3Contract(BaseModel):
    """Contract kind `s3_public`: who uses the bucket, and that none of it is public."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_name: str = Field(default=CONTRACT_SCHEMA, alias="schema")
    resource: str
    account: str | None = None
    region: str | None = None
    kind: Literal["s3_public"] = "s3_public"
    observed: ObservedMeta
    exposure: dict[str, Exposure] = Field(default_factory=dict)  # bucket -> exposure
    must_keep: list[S3Use] = Field(default_factory=list)
    must_block: list[str] = Field(
        default_factory=lambda: ["anonymous requests", "cross-account access via a public policy"]
    )
    needs_review: list[S3Use] = Field(default_factory=list)
    unknown_risk: str = ""
    status: Literal["draft", "approved"] = "draft"
    approved_by: str | None = None
    approved_at: str | None = None
    generated_by: str = ""
