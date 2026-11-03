"""Where a resource is defined in Terraform and who owns it (architecture doc 6.2)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from posturanet.models.common import Confidence


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    file: str
    line: int
    module_path: list[str] = Field(default_factory=list)
    state_source: str
    owners: list[str] = Field(default_factory=list)
    # None means "not checked yet" (needs terraform plan, R1). Never treat None as "no drift".
    drift: bool | None = None
    confidence: Confidence
    reasoning: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
