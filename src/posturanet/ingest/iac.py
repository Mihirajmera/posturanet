"""Terraform scanner reports (Checkov `-o json`, Trivy `config -f json`) -> Finding.

These scanners read code, not the cloud: a finding names a Terraform address such as
`aws_security_group.bastion`, not an AWS id. The address is resolved against the Terraform
state at locate time (`locate.resolve_address`). Check ids map to Security Hub controls through
`iac_checks.json`, which is curated by hand; unlisted checks are unsupported, never guessed.

Finding text is kept as data only. Nothing here interprets it (NFR-4).
"""

from __future__ import annotations

import json
import re
from functools import cache
from importlib.resources import files
from typing import Any, Literal

from pydantic import ValidationError

from posturanet.configfix.catalog import fixes_for
from posturanet.errors import StageStop
from posturanet.ingest.controls import fix_type_for
from posturanet.models import Finding, FixType, Provenance, ResourceRef, Severity

Tool = Literal["checkov", "trivy"]
_SEVERITIES = {s.value for s in Severity}
_ADDRESS = re.compile(
    r"^(?:module\.[A-Za-z0-9_-]+(?:\[[^\]]*\])?\.)*aws_[a-z0-9_]+\.[A-Za-z0-9_-]+"
)
_TERRAFORM_CHECK_TYPES = {"terraform", "terraform_plan"}


@cache
def check_map(tool: Tool) -> dict[str, list[str]]:
    raw = json.loads(files("posturanet.ingest").joinpath("iac_checks.json").read_text("utf-8"))
    mapped: dict[str, list[str]] = raw[tool]
    return mapped


# --- Checkov


def looks_like_checkov(doc: Any) -> bool:
    first = doc[0] if isinstance(doc, list) and doc else doc
    return isinstance(first, dict) and "check_type" in first and "results" in first


def checkov_items(doc: Any) -> list[dict[str, Any]]:
    reports = doc if isinstance(doc, list) else [doc]
    items: list[dict[str, Any]] = []
    for report in reports:
        if not isinstance(report, dict) or report.get("check_type") not in _TERRAFORM_CHECK_TYPES:
            continue
        failed = (report.get("results") or {}).get("failed_checks") or []
        items.extend(
            {**c, "_check_type": report["check_type"]} for c in failed if isinstance(c, dict)
        )
    return items


def checkov_document(item: dict[str, Any]) -> dict[str, Any]:
    """A one-finding Checkov report, for `posturanet findings split`."""
    check = {k: v for k, v in item.items() if k != "_check_type"}
    return {
        "check_type": item.get("_check_type", "terraform"),
        "results": {"failed_checks": [check]},
    }


def parse_checkov_item(item: dict[str, Any], *, raw_sha256: str) -> Finding:
    check_id = str(item.get("check_id") or "")
    result = item.get("check_result")
    status = str(result.get("result") if isinstance(result, dict) else "FAILED").upper()
    if status != "FAILED":
        raise StageStop(
            "ingest", f"check result is {status}: there is nothing to fix", ["pass a failed check"]
        )
    address = _address(str(item.get("resource_address") or item.get("resource") or ""))
    return _finding(
        "checkov",
        check_id=check_id,
        address=address,
        title=str(item.get("check_name") or ""),
        severity=str(item.get("severity") or ""),
        uid=f"checkov:{check_id}:{address}:{item.get('file_path', '')}",
        schema="checkov-json",
        raw_sha256=raw_sha256,
    )


# --- Trivy


def looks_like_trivy(doc: Any) -> bool:
    return isinstance(doc, dict) and "Results" in doc and "SchemaVersion" in doc


def trivy_items(doc: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for result in doc.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for m in result.get("Misconfigurations") or []:
            if isinstance(m, dict):
                items.append(
                    {
                        "Target": result.get("Target"),
                        "SchemaVersion": doc.get("SchemaVersion"),
                        "Misconfiguration": m,
                    }
                )
    return items


def trivy_document(item: dict[str, Any]) -> dict[str, Any]:
    """A one-finding Trivy report, for `posturanet findings split`."""
    return {
        "SchemaVersion": item.get("SchemaVersion", 2),
        "Results": [
            {
                "Target": item.get("Target"),
                "Class": "config",
                "Misconfigurations": [item["Misconfiguration"]],
            }
        ],
    }


def parse_trivy_item(item: dict[str, Any], *, raw_sha256: str) -> Finding:
    m = item.get("Misconfiguration")
    if not isinstance(m, dict):
        raise StageStop("ingest", "Trivy result has no misconfiguration")
    status = str(m.get("Status") or "FAIL").upper()
    if status != "FAIL":
        raise StageStop(
            "ingest", f"check status is {status}: there is nothing to fix", ["pass a failed check"]
        )
    check_id = str(m.get("ID") or m.get("AVDID") or "").removeprefix("AVD-")
    raw_cause = m.get("CauseMetadata")
    cause: dict[str, Any] = raw_cause if isinstance(raw_cause, dict) else {}
    address = _address(str(cause.get("Resource") or ""))
    return _finding(
        "trivy",
        check_id=check_id,
        address=address,
        title=str(m.get("Title") or ""),
        severity=str(m.get("Severity") or ""),
        uid=f"trivy:{check_id}:{address}:{item.get('Target', '')}:{cause.get('StartLine', '')}",
        schema=f"trivy-json-{item.get('SchemaVersion') or 'unknown'}",
        raw_sha256=raw_sha256,
    )


# --- shared


def control_for(tool: Tool, check_id: str, resource_type: str) -> str | None:
    """The control PosturaNet fixes for this check on this resource type, or None."""
    candidates = check_map(tool).get(check_id, [])
    if len(candidates) > 1:
        typed = [c for c in candidates if resource_type in {f.resource_type for f in fixes_for(c)}]
        candidates = typed or candidates
    if len(candidates) > 1:
        raise StageStop(
            "ingest",
            f"{check_id} maps to several controls: {', '.join(candidates)}",
            ["export a Security Hub finding for the control you want fixed"],
        )
    return candidates[0] if candidates else None


def _finding(
    tool: Tool,
    *,
    check_id: str,
    address: str,
    title: str,
    severity: str,
    uid: str,
    schema: str,
    raw_sha256: str,
) -> Finding:
    if not check_id or not address:
        missing = [n for n, v in (("check id", check_id), ("resource address", address)) if not v]
        raise StageStop(
            "ingest",
            f"{tool} finding is missing: {', '.join(missing)}",
            [f"run {tool} on Terraform with JSON output and pass that file"],
        )
    rtype = _resource_type(address)
    control = control_for(tool, check_id, rtype)
    label = severity.upper()
    try:
        return Finding(
            finding_id=uid,
            source=tool,
            control_id=control or check_id,
            title=title,
            severity=Severity(label) if label in _SEVERITIES else Severity.MEDIUM,
            resource=ResourceRef(type=rtype, id=address, address=address),
            fix_type=fix_type_for(control) if control else FixType.UNSUPPORTED,
            provenance=Provenance(raw_sha256=raw_sha256, schema_name=schema),
        )
    except ValidationError as exc:
        raise StageStop(
            "ingest", f"finding could not be normalized: {exc.errors()[0]['msg']}"
        ) from exc


def _address(raw: str) -> str:
    """`module.a.aws_x.b[0]` style address; drops anything a scanner appends after it."""
    match = _ADDRESS.match(raw.strip())
    if not match:
        return ""
    rest = raw.strip()[match.end() :]
    index = re.match(r"\[[^\]]*\]", rest)
    return match.group(0) + (index.group(0) if index else "")


def _resource_type(address: str) -> str:
    return re.sub(r"\[[^\]]*\]$", "", address).split(".")[-2]
