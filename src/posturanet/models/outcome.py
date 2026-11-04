"""Post-merge outcome and the verify spec a fix PR carries (architecture doc 6.8, 11)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class OutcomeState(StrEnum):
    OPENED = "OPENED"
    REJECTED = "REJECTED"
    MERGED = "MERGED"
    APPLIED = "APPLIED"
    CONFIRMED = "CONFIRMED"
    REGRESSED = "REGRESSED"
    REVERTED = "REVERTED"
    UNKNOWN = "UNKNOWN"


class VerifySpec(BaseModel):
    """What `posturanet verify` checks after merge. Written into the fix PR body."""

    model_config = ConfigDict(extra="forbid")

    v: Literal[1] = 1
    fix_type: str
    control: str
    finding_id: str
    resource_id: str
    resource_arn: str | None = None
    address: str
    key: str  # idempotency key of the fix PR
    watch_hours: int = 72
    # config_attribute: catalog changes, as dicts ({path, op, value, allowed})
    changes: list[dict[str, Any]] = Field(default_factory=list)
    # sg_ingress: rules after the fix ([cidr, from, to, proto]) and the contract's must_allow
    rules: list[tuple[str, int, int, str]] = Field(default_factory=list)
    must_allow: list[tuple[str, int, str]] = Field(default_factory=list)


class Outcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: OutcomeState
    pr: str
    finding_id: str
    control: str
    address: str
    merged_at: datetime | None = None
    merge_sha: str | None = None
    watch_from: datetime | None = None
    watch_until: datetime | None = None
    regressions: list[str] = Field(default_factory=list)
    revert_pr: str | None = None
