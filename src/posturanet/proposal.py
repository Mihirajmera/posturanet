"""Everything a validated fix carries into delivery, the PR body and MCP responses."""

from __future__ import annotations

from dataclasses import dataclass, field

from posturanet.models import (
    BehaviorContract,
    Confidence,
    Diff,
    Finding,
    Location,
    Observations,
    ReportStatus,
    ValidationReport,
)
from posturanet.synth.sg_z3 import Synthesis


@dataclass
class Proposal:
    finding: Finding
    location: Location
    observations: Observations
    contract: BehaviorContract
    contract_file: str  # repo-relative
    contract_text: str | None  # new YAML to commit, or None when an approved contract is used
    synthesis: Synthesis
    diff: Diff
    report: ValidationReport
    idempotency_key: str
    unknowns: list[str] = field(default_factory=list)

    @property
    def issue(self) -> str:
        from posturanet.deliver.idempotency import issue  # deliver imports this module

        return issue(self.finding.control_id, self.location.address)

    @property
    def needs_review(self) -> bool:
        return bool(self.contract.needs_review)

    @property
    def risk(self) -> str:
        if self.observations.confidence is Confidence.HIGH and not self.needs_review:
            return "low"
        if self.observations.confidence in (Confidence.HIGH, Confidence.MEDIUM):
            return "medium"
        return "high"

    @property
    def disruption(self) -> str:
        # Every contract source stays allowed by construction; medium evidence can miss some.
        return "none" if self.observations.confidence is Confidence.HIGH else "possible"

    @property
    def validated(self) -> bool:
        return self.report.status is ReportStatus.PASS
