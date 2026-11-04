"""Run record written for every run (NFR-9, architecture doc 6.10)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from posturanet.models.finding import Finding
from posturanet.models.location import Location
from posturanet.models.observations import Observations
from posturanet.models.outcome import Outcome
from posturanet.models.s3 import S3Evidence
from posturanet.models.validation import Diff, ValidationReport


class StageStatus(StrEnum):
    OK = "ok"
    FAIL = "fail"
    WARN = "warn"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


class StageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    status: StageStatus
    summary: str
    details: list[str] = Field(default_factory=list)
    expand: bool = False  # always show details (e.g. observed sources), not only on failure


class RunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_version: str
    command: str
    target: str
    mode: str
    started_at: datetime
    stages: list[StageResult] = Field(default_factory=list)
    finding: Finding | None = None
    location: Location | None = None
    observations: Observations | None = None
    s3_evidence: S3Evidence | None = None  # S3 public-access fixes only
    contract_file: str | None = None
    diff: Diff | None = None
    validation: ValidationReport | None = None
    pr_url: str | None = None
    outcome: Outcome | None = None  # verify runs only
    result: str
    result_detail: str = ""
    why: str | None = None
    unknowns: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    exit_code: int = 0
