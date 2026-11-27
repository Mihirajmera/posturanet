"""OCSF-aligned internal finding (architecture doc 6.1)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from posturanet.models.common import FixType, Severity

# Finding text comes from scanners. Terminal control characters (ANSI/OSC escapes) in it could
# rewrite what `posturanet` prints, so they are dropped on the way in; tab and newline stay.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _no_control(v: Any) -> Any:
    return _CONTROL.sub("", v) if isinstance(v, str) else v


class ResourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    _clean = field_validator("*", mode="before")(_no_control)

    type: str
    id: str
    arn: str | None = None
    account: str | None = None
    region: str | None = None
    # Terraform address reported by an IaC scanner (Checkov, Trivy). Until locate resolves it
    # against the state, `id` holds the address too.
    address: str | None = None


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    raw_sha256: str
    schema_name: str = Field(alias="schema")


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    _clean = field_validator("*", mode="before")(_no_control)

    finding_id: str
    source: str
    control_id: str
    title: str
    severity: Severity
    resource: ResourceRef
    fix_type: FixType
    observed_at: datetime | None = None
    provenance: Provenance
