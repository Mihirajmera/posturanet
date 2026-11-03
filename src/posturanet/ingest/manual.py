"""Manual target -> Finding (FR-2)."""

from __future__ import annotations

import hashlib

from posturanet.errors import UsageError
from posturanet.ingest.controls import fix_type_for
from posturanet.models import Finding, FixType, Provenance, ResourceRef, Severity

_PREFIXES: dict[str, tuple[str, FixType]] = {
    "sg-": ("AwsEc2SecurityGroup", FixType.SG_INGRESS),
}


def finding_from_resource_id(resource_id: str, control_id: str | None = None) -> Finding:
    resource_id = resource_id.strip()
    rtype, fix_type = next(
        (v for p, v in _PREFIXES.items() if resource_id.startswith(p)), ("unknown", None)
    )
    if control_id:
        fix_type = fix_type_for(control_id)
    if fix_type is None:
        raise UsageError(
            f"can't tell what kind of resource '{resource_id}' is; "
            "pass an ASFF finding file instead, or a security group id (sg-...)"
        )
    return Finding(
        finding_id=f"manual:{resource_id}",
        source="manual",
        control_id=control_id or "manual",
        title="Manual target",
        severity=Severity.MEDIUM,
        resource=ResourceRef(type=rtype, id=resource_id),
        fix_type=fix_type,
        provenance=Provenance(
            raw_sha256=hashlib.sha256(resource_id.encode()).hexdigest(), schema_name="manual"
        ),
    )
