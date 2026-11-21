"""Living contracts: what `contract refresh` proposes for one contract (FR-52, FR-54)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RefreshStatus = Literal["PASS", "PROPOSED", "UNKNOWN", "SKIPPED"]


class RefreshChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    section: str  # contract section the entry is (or would be) in: must_allow, must_keep, ...
    entry: str  # "10.0.9.4/32 → 22/tcp", "s3:GetObject", a requester
    detail: str  # what the evidence says about it


class ContractRefresh(BaseModel):
    """Approved contract vs fresh evidence. The contract file itself is never edited here: a
    proposal is a new contract text, delivered as a PR a person approves."""

    model_config = ConfigDict(extra="forbid")

    resource: str
    contract_file: str
    kind: str
    status: RefreshStatus
    evidence: str = ""  # "vpc flow logs · 90 days · confidence high"
    additions: list[RefreshChange] = Field(default_factory=list)  # new real users
    removals: list[RefreshChange] = Field(default_factory=list)  # not seen: flagged, kept
    reasons: list[str] = Field(default_factory=list)  # why UNKNOWN or SKIPPED
    proposed: str | None = None  # the proposed contract YAML (PROPOSED only)
    pr_url: str | None = None
    pr_action: str | None = None  # opened | updated | unchanged
