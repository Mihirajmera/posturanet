"""Proposed change and its validation report (architecture doc 6.5, 6.6)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, computed_field


class FileChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str  # repo-relative, forward slashes
    unified_diff: str
    new_content: str


class Diff(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_address: str
    files: list[FileChange] = Field(default_factory=list)
    summary: str  # e.g. "0.0.0.0/0:22 -> 10.0.4.0/24:22 (1 rule)"
    rules_before: list[str] = Field(default_factory=list)
    rules_after: list[str] = Field(default_factory=list)
    generator: str = "template:sg_ingress@1"
    sha256: str = ""


class CheckResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"


class ReportStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    required: bool
    result: CheckResult
    detail: str = ""
    model_scope: str | None = None


class ValidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checks: list[Check] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status(self) -> ReportStatus:
        required = [c for c in self.checks if c.required]
        if any(c.result is CheckResult.FAIL for c in required):
            return ReportStatus.FAIL
        if any(c.result is not CheckResult.PASS for c in required):
            return ReportStatus.INCOMPLETE
        return ReportStatus.PASS
