"""IAM least-privilege evidence and contract (FR-16, FR-51, architecture doc 14.3)."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from posturanet.models.common import Confidence
from posturanet.models.contract import CONTRACT_SCHEMA, ObservedMeta


class TrackedUse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str  # "s3:ListAllMyBuckets"
    last_seen: date | None = None


class ServiceAccess(BaseModel):
    model_config = ConfigDict(extra="forbid")

    namespace: str
    last_accessed: date | None = None  # service level; None: not used in the tracking period
    action_level: bool  # IAM tracks actions for this service
    actions: list[TrackedUse] = Field(default_factory=list)  # tracked actions, used or not


class IamEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_arn: str
    source: str  # "iam_last_accessed" or "iam_evidence_file"
    created: date | None = None
    age_days: int
    principals: list[str] = Field(default_factory=list)
    services: list[ServiceAccess] = Field(default_factory=list)
    confidence: Confidence

    def used(self) -> list[TrackedUse]:
        return sorted(
            (a for s in self.services for a in s.actions if a.last_seen is not None),
            key=lambda a: a.action.lower(),
        )


class IamAllowed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    last_seen: date | None = None
    source: Literal["last_accessed", "human"] = "last_accessed"
    owner: str | None = None
    ref: str | None = None


class IamContract(BaseModel):
    """Contract kind `iam`: the actions the policy must keep allowing."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_name: str = Field(default=CONTRACT_SCHEMA, alias="schema")
    resource: str
    account: str | None = None
    kind: Literal["iam"] = "iam"
    policy_arn: str
    observed: ObservedMeta
    principals: list[str] = Field(default_factory=list)
    must_allow: list[IamAllowed] = Field(default_factory=list)
    must_remove: list[str] = Field(default_factory=list)  # wildcard actions the fix replaces
    reviewed_services: list[str] = Field(default_factory=list)
    needs_review: list[str] = Field(default_factory=list)  # one line per blocker
    unknown_risk: str = ""
    status: Literal["draft", "approved"] = "draft"
    approved_by: str | None = None
    approved_at: str | None = None
    generated_by: str = ""
