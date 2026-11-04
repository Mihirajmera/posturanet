"""Behavior contract kept in the customer's repo (architecture doc 6.4)."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from posturanet.models.common import Confidence

CONTRACT_SCHEMA = "posturanet.contract/v1"


class NetRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str
    port: int
    proto: str
    period: str | None = None
    owner: str | None = None
    ref: str | None = None
    count: int | None = None
    reason: str | None = None  # why a source is in needs_review or not_kept


class ObservedWindow(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    start: date = Field(alias="from")
    end: date = Field(alias="to")
    days: int


class ObservedMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    window: ObservedWindow
    confidence: Confidence


class BehaviorContract(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_name: str = Field(default=CONTRACT_SCHEMA, alias="schema")
    resource: str
    account: str | None = None
    region: str | None = None
    kind: Literal["network"] = "network"
    observed: ObservedMeta
    must_allow: list[NetRule] = Field(default_factory=list)
    must_deny: list[NetRule] = Field(default_factory=list)
    needs_review: list[NetRule] = Field(default_factory=list)
    # Observed but left out of the fix (likely scanners). Move one to must_allow to keep it.
    not_kept: list[NetRule] = Field(default_factory=list)
    unknown_risk: str = ""
    status: Literal["draft", "approved"] = "draft"
    approved_by: str | None = None
    approved_at: str | None = None
    generated_by: str = ""
