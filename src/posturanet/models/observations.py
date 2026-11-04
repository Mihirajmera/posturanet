"""Observed usage of a resource (architecture doc 6.3)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from posturanet.models.common import Confidence


class Period(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    IRREGULAR = "irregular"
    RARE = "rare"
    ONE_OFF = "one_off"


class Window(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    start: datetime = Field(alias="from")
    end: datetime = Field(alias="to")
    days: int
    coverage_ratio: float
    max_gap_hours: int


class ObservedFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str  # always a single address (/32 or /128); collapsing happens only in synthesis
    port: int
    proto: str
    count: int
    bytes: int | None = None  # total bytes, when the source reports them
    first_seen: datetime
    last_seen: datetime
    days_seen: int
    period: Period
    needs_review: bool = False
    hours_histogram: list[int] = Field(default_factory=lambda: [0] * 24)


class Observations(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_address: str
    kind: str = "network"
    source: str  # "vpc_flow_logs" or "flow_logs_file"
    enis: list[str] = Field(default_factory=list)
    window: Window
    items: list[ObservedFlow] = Field(default_factory=list)
    confidence: Confidence
