"""`.posturanet/exceptions.yaml`: findings a team accepted, each with an owner and an expiry."""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, Field


class AcceptedRisk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    control: str = Field(min_length=1)
    resource: str | None = None  # None: every resource failing this control
    owner: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    expires: date

    def matches(self, control: str | None, resource: str | None) -> bool:
        return control == self.control and self.resource in (None, resource)


class ExceptionsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exceptions: list[AcceptedRisk] = Field(default_factory=list)
