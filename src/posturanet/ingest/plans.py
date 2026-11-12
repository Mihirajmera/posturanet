"""Security Hub remediation plans (GetRemediationsV2) -> one Finding per plan (FR-4c).

A plan targets one resource and groups the exposure findings that share a root cause. It
names no control id: the controls come from the exposure findings it links, whose
`finding_info.related_events` carry the control findings ("RDS.8 RDS DB ..."). PosturaNet
fixes the linked controls it supports on the plan's resource as one change, so one plan
becomes one PR. AWS's guidance text and Terraform example are kept as data only (NFR-4);
the change itself comes from the catalog.

`posturanet findings pull-plans` writes the file this module reads. A bare GetRemediationsV2
response also reads, but without exposure findings no controls are known.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from pydantic import ValidationError

from posturanet.configfix.catalog import fixes_for
from posturanet.errors import StageStop
from posturanet.ingest.controls import fix_type_for
from posturanet.ingest.ocsf import related_controls
from posturanet.models import Finding, FixType, Provenance, ResourceRef, Severity

MARKER = "PosturaNetRemediationPlans"
_PRIORITY = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
}
_PULL = "pull them with their exposure findings: `posturanet findings pull-plans`"


def looks_like_plans(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    if MARKER in doc:
        return True
    items = doc.get("Items")
    return (
        isinstance(items, list)
        and bool(items)
        and all(isinstance(i, dict) and "TargetUid" in i and "Trait" in i for i in items)
    )


def plan_items(doc: dict[str, Any]) -> list[dict[str, Any]]:
    plans = doc.get("Plans") if MARKER in doc else doc.get("Items")
    return [p for p in plans or [] if isinstance(p, dict)]


def plan_document(item: dict[str, Any]) -> dict[str, Any]:
    """A one-plan file, for `posturanet findings split`."""
    return {MARKER: "1", "Plans": [item]}


def linked_controls(item: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for exposure in item.get("ExposureFindings") or []:
        if isinstance(exposure, dict):
            found += [c for c in related_controls(exposure) if c not in found]
    return found


def choose_controls(linked: list[str]) -> tuple[list[str], list[str]]:
    """(controls fixed together on the plan's resource, fixable controls left out).

    Attribute fixes merge into one change when they share a Terraform resource type; the
    type most of them fit wins. Evidence fixes (security groups, S3, IAM) run one at a time.
    """
    fixable = [c for c in linked if fix_type_for(c) is not FixType.UNSUPPORTED]
    attr = [c for c in fixable if fix_type_for(c) is FixType.CONFIG_ATTRIBUTE]
    if attr:
        types = Counter(t for c in attr for t in {f.resource_type for f in fixes_for(c)})
        top = max(types.values())
        best = {t for t, n in types.items() if n == top}
        chosen = [c for c in attr if best & {f.resource_type for f in fixes_for(c)}]
        if len(chosen) > 1 and not fixes_for("+".join(chosen)):
            chosen = chosen[:1]  # the rows conflict; fix the first, list the rest
    else:
        chosen = fixable[:1]
    return chosen, [c for c in fixable if c not in chosen]


def parse_plan_item(item: dict[str, Any], *, raw_sha256: str) -> Finding:
    uid = str(item.get("TargetUid") or "")
    res = item.get("Resource")
    if not uid or not isinstance(res, dict) or not res.get("Id"):
        raise StageStop(
            "ingest",
            "remediation plan is missing TargetUid or Resource.Id",
            ["export the plans again with `posturanet findings pull-plans`"],
        )
    status = str(item.get("Status") or "")
    if status == "Resolved":
        raise StageStop("ingest", "plan is Resolved: there is nothing to fix", [])
    if "ExposureFindings" not in item:
        raise StageStop("ingest", f"plan has no exposure findings attached; {_PULL}", [_PULL])

    linked = linked_controls(item)
    chosen, left = choose_controls(linked)
    if not chosen:
        raise StageStop(
            "ingest",
            "plan links "
            + (f"controls {', '.join(linked)}, none of which" if linked else "no control that")
            + " PosturaNet fixes yet",
            ["apply the plan's guidance by hand, or check `posturanet fixes list`"],
        )
    control = "+".join(chosen)
    summary = _obj(item.get("RemediationSummary"))
    title = str(summary.get("Action") or _obj(item.get("Trait")).get("Title") or "")
    if left:
        title += f" (also linked, fix separately: {', '.join(left)})"
    rid = str(res["Id"])
    try:
        return Finding(
            finding_id=uid,
            source="security hub plan",
            control_id=control,
            title=title,
            severity=_PRIORITY.get(str(item.get("Priority") or ""), Severity.MEDIUM),
            resource=ResourceRef(
                type=str(res.get("Type") or "unknown"),
                id=rid.rsplit("/", 1)[-1].rsplit(":", 1)[-1] if rid.startswith("arn:") else rid,
                arn=rid if rid.startswith("arn:") else None,
                account=str(res.get("ResourceOwnerAccountId") or res.get("AccountId") or "")
                or None,
                region=str(res.get("ResourceRegion") or res.get("Region") or "") or None,
            ),
            fix_type=fix_type_for(control),
            provenance=Provenance(raw_sha256=raw_sha256, schema_name="securityhub-remediation-v2"),
        )
    except ValidationError as exc:
        raise StageStop(
            "ingest", f"plan could not be normalized: {exc.errors()[0]['msg']}"
        ) from exc


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
