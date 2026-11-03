"""OCSF-aligned internal finding (architecture doc 6.1)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from posturanet.models.common import FixType, Severity


class ResourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    id: str
    arn: str | None = None
    account: str | None = None
    region: str | None = None


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    raw_sha256: str
    schema_name: str = Field(alias="schema")


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    source: str
    control_id: str
    title: str
    severity: Severity
    resource: ResourceRef
    fix_type: FixType
    observed_at: datetime | None = None
    provenance: Provenance
