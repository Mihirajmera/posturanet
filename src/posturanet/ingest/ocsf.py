"""OCSF findings (Prowler `json-ocsf`, Security Hub via Security Lake) -> Finding.

Prowler writes OCSF Detection Findings (class 2004) with its check id in `metadata.event_code`
and, under `unmapped.compliance`, the AWS Foundational Security Best Practices control ids the
check maps to. OCSF Compliance Findings carry the control id in `compliance.control`.

Finding text is kept as data only. Nothing here interprets it (NFR-4).
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from functools import cache
from importlib.resources import files
from typing import Any

from pydantic import ValidationError

from posturanet.configfix.catalog import same_fix
from posturanet.errors import StageStop, UsageError
from posturanet.ingest.controls import fix_type_for
from posturanet.models import Finding, FixType, Provenance, ResourceRef, Severity

FSBP = "AWS-Foundational-Security-Best-Practices"
_SEVERITIES = {s.value for s in Severity}
_SEVERITY_ALIASES = {"FATAL": Severity.CRITICAL}


def looks_like_ocsf(item: dict[str, Any]) -> bool:
    return "class_uid" in item or "finding_info" in item


def unwrap(doc: Any) -> Any:
    """The OCSF findings inside a Security Hub wrapper, or `doc` unchanged.

    `aws securityhub get-findings-v2` writes {"Findings": [...]}, which is ASFF's key, so
    the items decide; an EventBridge "Findings Imported V2" event holds them in
    detail.findings.
    """
    if not isinstance(doc, dict):
        return doc
    detail = _obj(doc.get("detail"))
    if doc.get("source") == "aws.securityhub" and isinstance(detail.get("findings"), list):
        return detail["findings"]
    listed = doc.get("Findings")
    if (
        isinstance(listed, list)
        and listed
        and all(isinstance(x, dict) and looks_like_ocsf(x) for x in listed)
    ):
        return listed
    return doc


def findings_in(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, dict):
        return [doc]
    if isinstance(doc, list) and all(isinstance(x, dict) for x in doc):
        return list(doc)
    raise UsageError("unrecognized OCSF document: expected an object or a list of findings")


@cache
def prowler_checks() -> dict[str, list[str]]:
    raw = files("posturanet.ingest").joinpath("prowler_checks.json").read_text("utf-8")
    checks: dict[str, list[str]] = json.loads(raw)["checks"]
    return checks


def parse_ocsf_item(item: dict[str, Any], *, raw_sha256: str) -> Finding:
    info = _obj(item.get("finding_info"))
    resources = item.get("resources")
    if not info.get("uid") or not isinstance(resources, list) or not resources:
        missing = [
            k
            for k, ok in (("finding_info.uid", info.get("uid")), ("resources", resources))
            if not ok
        ]
        raise StageStop(
            "ingest",
            f"finding is missing required fields: {', '.join(missing)}",
            ["export the findings again, e.g. `prowler aws --output-formats json-ocsf`"],
        )
    status = str(item.get("status_code") or "").upper()
    if status and status != "FAIL":
        raise StageStop(
            "ingest",
            f"finding status is {status}: there is nothing to fix",
            ["pass a failed finding (status_code FAIL)"],
        )
    # Security Hub's compliance findings carry the result here and have no status_code.
    result = str(_obj(item.get("compliance")).get("status") or "").upper()
    if result and result != "FAIL":
        raise StageStop(
            "ingest",
            f"control result is {result}: there is nothing to fix",
            ["pass a failed finding (compliance.status Fail)"],
        )

    control_id = control_id_of(item)
    linked = related_controls(item)
    if control_id is None and linked:
        fixable = [c for c in linked if fix_type_for(c) is not FixType.UNSUPPORTED]
        raise StageStop(
            "ingest",
            f"exposure finding: it links control findings {', '.join(linked)}"
            + (f", and PosturaNet fixes {', '.join(fixable)}" if fixable else ""),
            ["fix the linked control findings, or pass the Security Hub remediation plan"],
        )
    meta = _obj(item.get("metadata"))
    product = str(_obj(meta.get("product")).get("name") or "").strip().lower()
    try:
        return Finding(
            finding_id=str(info["uid"]),
            source=product or "ocsf",
            control_id=control_id or "unknown",
            title=str(info.get("title") or ""),
            severity=_severity(item),
            resource=_resource_ref(_obj(resources[0]), item),
            fix_type=fix_type_for(control_id or ""),
            observed_at=_timestamp(item, info),
            provenance=Provenance(
                raw_sha256=raw_sha256, schema_name=f"ocsf-{meta.get('version') or 'unknown'}"
            ),
        )
    except ValidationError as exc:
        raise StageStop(
            "ingest", f"finding could not be normalized: {exc.errors()[0]['msg']}"
        ) from exc


def control_id_of(item: dict[str, Any]) -> str | None:
    """The Security Hub control id, or None. Several candidates: the one PosturaNet fixes."""
    candidates = _control_candidates(item)
    fixable = [c for c in candidates if fix_type_for(c) is not FixType.UNSUPPORTED]
    if len(fixable) > 1 and same_fix(fixable):
        fixable = fixable[:1]
    if len(fixable) > 1:
        raise StageStop(
            "ingest",
            f"the finding maps to several controls PosturaNet fixes: {', '.join(fixable)}",
            ["export a Security Hub finding for the control you want fixed"],
        )
    if fixable:
        return fixable[0]
    return candidates[0] if candidates else None


def _control_candidates(item: dict[str, Any]) -> list[str]:
    control = _obj(item.get("compliance")).get("control")
    if control:
        return [str(control)]
    mapped = _obj(_obj(item.get("unmapped")).get("compliance"))
    found: set[str] = set()
    for framework, ids in mapped.items():
        if str(framework).startswith(FSBP) and isinstance(ids, list):
            found.update(str(i) for i in ids)
    if found:
        return sorted(found)
    check = str(_obj(item.get("metadata")).get("event_code") or "")
    return list(prowler_checks().get(check, []))


_CONTROL_TITLE = re.compile(r"^([A-Za-z][A-Za-z0-9]*\.\d+)\s")


def related_controls(item: dict[str, Any]) -> list[str]:
    """Control ids an exposure finding links in finding_info.related_events, in order.

    Security Hub titles a linked control finding "<control> <title>" ("RDS.8 RDS DB ...").
    """
    found: list[str] = []
    for event in _obj(item.get("finding_info")).get("related_events") or []:
        event = _obj(event)
        m = _CONTROL_TITLE.match(str(event.get("title") or ""))
        if event.get("type") == "Finding" and m and m.group(1) not in found:
            found.append(m.group(1))
    return found


def _resource_ref(res: dict[str, Any], item: dict[str, Any]) -> ResourceRef:
    uid = str(res.get("uid") or "")
    # arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a91f3c2 -> sg-0a91f3c2
    rid = re.split(r"[/:]", uid)[-1] if uid.startswith("arn:") else uid
    rid = rid or str(res.get("name") or "")
    if not rid:
        raise StageStop("ingest", "could not determine the resource id from the finding")
    cloud = _obj(item.get("cloud"))
    account = _obj(cloud.get("account")).get("uid")
    region = res.get("region") or cloud.get("region")
    return ResourceRef(
        type=str(res.get("type") or "unknown"),
        id=rid,
        arn=uid if uid.startswith("arn:") else None,
        account=str(account) if account else None,
        region=str(region) if region else None,
    )


def _severity(item: dict[str, Any]) -> Severity:
    label = str(item.get("severity") or "").upper()
    if label in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[label]
    return Severity(label) if label in _SEVERITIES else Severity.MEDIUM


def _timestamp(item: dict[str, Any], info: dict[str, Any]) -> datetime | None:
    for value in (info.get("created_time_dt"), item.get("time_dt")):
        if value:
            try:
                return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except ValueError:
                pass
    epoch = info.get("created_time") or item.get("time")
    if isinstance(epoch, int | float) and epoch > 0:
        # OCSF says milliseconds; Prowler writes seconds.
        return datetime.fromtimestamp(epoch / 1000 if epoch > 1e11 else epoch, tz=UTC)
    return None


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
