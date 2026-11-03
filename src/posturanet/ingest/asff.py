"""AWS Security Finding Format (ASFF) -> Finding (FR-1, FR-3, FR-4).

Finding text (titles, descriptions) is kept as data only. Nothing here interprets it (NFR-4).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from posturanet.errors import StageStop, UsageError
from posturanet.ingest.controls import fix_type_for
from posturanet.models import Finding, Provenance, ResourceRef, Severity

ASFF_SCHEMA = "asff-2018-10-08"
_CONTROL_IN_GENERATOR = re.compile(r"/([A-Za-z0-9]+\.\d+)$")
_SEVERITIES = {s.value for s in Severity}


def parse_asff_file(path: Path) -> Finding:
    if not path.is_file():
        raise UsageError(f"finding file not found: {path}")
    raw = path.read_bytes()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UsageError(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    return parse_asff(doc, raw_sha256=hashlib.sha256(raw).hexdigest())


def parse_asff(doc: Any, *, raw_sha256: str) -> Finding:
    items = _findings_in(doc)
    if len(items) != 1:
        raise UsageError(
            f"expected exactly 1 finding, got {len(items)}; pass a file with a single finding"
        )
    item = items[0]

    missing = [k for k in ("Id", "Resources", "Severity") if k not in item]
    if missing:
        raise StageStop(
            "ingest",
            f"finding is missing required fields: {', '.join(missing)}",
            ["export the finding again from Security Hub (ASFF JSON)"],
        )
    resources = item["Resources"]
    if not isinstance(resources, list) or not resources:
        raise StageStop("ingest", "finding has no resources", ["check the finding in Security Hub"])

    control_id = _control_id(item)
    resource = _resource_ref(resources[0], item)
    try:
        return Finding(
            finding_id=str(item["Id"]),
            source="securityhub",
            control_id=control_id or "unknown",
            title=str(item.get("Title", "")),
            severity=_severity(item),
            resource=resource,
            fix_type=fix_type_for(control_id or ""),
            observed_at=_timestamp(item),
            provenance=Provenance(raw_sha256=raw_sha256, schema_name=ASFF_SCHEMA),
        )
    except ValidationError as exc:
        raise StageStop(
            "ingest", f"finding could not be normalized: {exc.errors()[0]['msg']}"
        ) from exc


def _findings_in(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, dict) and "Findings" in doc:
        doc = doc["Findings"]
    if isinstance(doc, dict):
        return [doc]
    if isinstance(doc, list) and all(isinstance(x, dict) for x in doc):
        return list(doc)
    raise UsageError(
        "unrecognized ASFF document: expected an object, a list, or {'Findings': [...]}"
    )


def _control_id(item: dict[str, Any]) -> str | None:
    compliance = item.get("Compliance") or {}
    if isinstance(compliance, dict) and compliance.get("SecurityControlId"):
        return str(compliance["SecurityControlId"])
    product_fields = item.get("ProductFields") or {}
    if isinstance(product_fields, dict) and product_fields.get("ControlId"):
        return str(product_fields["ControlId"])
    match = _CONTROL_IN_GENERATOR.search(str(item.get("GeneratorId", "")))
    return match.group(1) if match else None


def _resource_ref(res: dict[str, Any], item: dict[str, Any]) -> ResourceRef:
    arn = str(res.get("Id", ""))
    details = res.get("Details") or {}
    sg = details.get("AwsEc2SecurityGroup") if isinstance(details, dict) else None
    if isinstance(sg, dict) and sg.get("GroupId"):
        rid = str(sg["GroupId"])
    else:
        # arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a91f3c2 -> sg-0a91f3c2
        rid = re.split(r"[/:]", arn)[-1] if arn else ""
    if not rid:
        raise StageStop("ingest", "could not determine the resource id from the finding")
    return ResourceRef(
        type=str(res.get("Type", "unknown")),
        id=rid,
        arn=arn if arn.startswith("arn:") else None,
        account=str(item["AwsAccountId"]) if item.get("AwsAccountId") else None,
        region=str(res.get("Region") or item.get("Region") or "") or None,
    )


def _severity(item: dict[str, Any]) -> Severity:
    sev = item.get("Severity") or {}
    label = str(sev.get("Label", "")).upper() if isinstance(sev, dict) else ""
    return Severity(label) if label in _SEVERITIES else Severity.MEDIUM


def _timestamp(item: dict[str, Any]) -> datetime | None:
    value = item.get("UpdatedAt") or item.get("CreatedAt")
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
