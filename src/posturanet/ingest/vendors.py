"""Wiz, Orca and Prisma Cloud exports -> Finding (FR-4d, R5).

A vendor rule maps to a PosturaNet control only when the export itself names a supported AWS
Foundational Security Best Practices or CIS AWS control id, or the customer maps it in
`.posturanet.yml` (`detectors.<vendor>.rules`). There is no built-in vendor-rule table: an
unmapped rule still ends in an outcome (`none`, with the reason), never a guessed control.

Formats, each read only from public documentation of the vendor's API:
- Prisma Cloud: List Alerts (`GET /alert`, a list) and List Alerts V2 (`GET|POST /v2/alert`,
  `{"items": [...]}`), schema `AlertModel` in Palo Alto Networks' OpenAPI spec
  https://raw.githubusercontent.com/PaloAltoNetworks/pan.dev/master/openapi-specs/cspm/Alerts.json
  (rendered at https://pan.dev/prisma-cloud/api/cspm/get-alerts-v-2/).
- Wiz: the GraphQL `issuesV2` query result (`{"data": {"issues": {"nodes": [...]}}}`), as
  queried by the public Cortex XSOAR Wiz integration,
  https://github.com/demisto/content/blob/master/Packs/Wiz/Integrations/Wiz/Wiz.py
  (Wiz's own reference, https://win.wiz.io/reference/issues-query, needs a login).
- Orca: the serving-layer alert query (`POST /api/serving-layer/query`, `{"data": [...]}`),
  as used by the public Cortex XSOAR Orca event collector and its sample response,
  https://github.com/demisto/content/blob/master/Packs/Orca/Integrations/OrcaEventCollector/OrcaEventCollector.py
  https://github.com/demisto/content/blob/master/Packs/Orca/Integrations/OrcaEventCollector/test_data/get_alerts_test.json
  Orca alerts carry no control ids, so they map through the customer's file only.

CSV exports are not read: none of the three vendors documents its CSV columns publicly.
The refusal points to `docs/vendor-exports.md`, which has the JSON export commands.

Finding text is kept as data only. Nothing here interprets it (NFR-4).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import ValidationError

from posturanet.configfix.catalog import same_fix
from posturanet.errors import StageStop
from posturanet.ingest.controls import fix_type_for
from posturanet.models import Finding, FixType, Provenance, ResourceRef, Severity

Vendor = Literal["wiz", "orca", "prisma"]
VENDORS: tuple[Vendor, ...] = ("wiz", "orca", "prisma")
NAMES: dict[Vendor, str] = {"wiz": "Wiz", "orca": "Orca", "prisma": "Prisma Cloud"}
Rules = Mapping[str, Mapping[str, str]]  # vendor -> {vendor rule id: control}

_SEVERITIES = {s.value for s in Severity}
_CONTROL = re.compile(r"^([A-Za-z][A-Za-z0-9]*\.\d+)(?:\s|$)")  # "EC2.19", "EC2.19 Security ..."
_FRAMEWORK = re.compile(
    r"foundational security best practices|\bcis\b.*\baws\b|\baws\b.*\bcis\b", re.IGNORECASE
)
_ACCOUNT = re.compile(r"^\d{12}$")


# --- detection and items


def detect(doc: Any) -> tuple[Vendor, list[dict[str, Any]]] | None:
    """The vendor and its alert objects, or None when `doc` isn't a vendor export."""
    if isinstance(doc, dict):
        data = doc.get("data")
        if isinstance(data, dict):  # Wiz GraphQL response; XSOAR aliases issuesV2 as `issues`
            conn = data.get("issues") or data.get("issuesV2")
            nodes = conn.get("nodes") if isinstance(conn, dict) else None
            if isinstance(nodes, list):
                return "wiz", _dicts(nodes)
        if isinstance(data, list) and data and all(_is_orca(x) for x in data):
            return "orca", _dicts(data)
        items = doc.get("items")
        if isinstance(items, list) and items and all(_is_prisma(x) for x in items):
            return "prisma", _dicts(items)
        return None
    if isinstance(doc, list) and doc:
        for vendor, test in (("wiz", _is_wiz), ("orca", _is_orca), ("prisma", _is_prisma)):
            if all(test(x) for x in doc):
                return vendor, _dicts(doc)  # type: ignore[return-value]
    return None


def document_for(item: dict[str, Any], vendor: Vendor) -> dict[str, Any]:
    """A one-alert export in the vendor's own shape, for `posturanet findings split`."""
    if vendor == "wiz":
        return {"data": {"issues": {"nodes": [item]}}}
    if vendor == "orca":
        return {"status": "success", "data": [item]}
    return {"items": [item]}


def _is_wiz(x: Any) -> bool:
    return isinstance(x, dict) and "sourceRule" in x and "entitySnapshot" in x


def _is_orca(x: Any) -> bool:
    return isinstance(x, dict) and x.get("type") == "Alert" and "AlertId" in _obj(x.get("data"))


def _is_prisma(x: Any) -> bool:
    return isinstance(x, dict) and "alertTime" in x and "resource" in x and "policyId" in x


def _dicts(xs: list[Any]) -> list[dict[str, Any]]:
    return [x for x in xs if isinstance(x, dict)]


# --- parsing


def parse_item(
    item: dict[str, Any], vendor: Vendor, *, raw_sha256: str, rules: Rules | None = None
) -> Finding:
    if vendor == "wiz":
        fields = _wiz(item)
    elif vendor == "orca":
        fields = _orca(item)
    else:
        fields = _prisma(item)
    rule_id, uid, title, severity, status, closed, res, observed, listed = fields
    if not rule_id or not uid or not res.id:
        missing = [
            n for n, v in (("rule id", rule_id), ("alert id", uid), ("resource", res.id)) if not v
        ]
        raise StageStop(
            "ingest",
            f"{NAMES[vendor]} alert is missing: {', '.join(missing)}",
            [f"export the {NAMES[vendor]} alerts again as JSON from its API"],
        )
    if status.lower() in closed:
        raise StageStop(
            "ingest",
            f"alert status is {status}: there is nothing to fix",
            ["pass an open alert"],
        )
    control = control_for(vendor, rule_id, listed, rules)
    label = severity.upper()
    try:
        return Finding(
            finding_id=f"{vendor}:{uid}",
            source=vendor,
            control_id=control or rule_id,
            title=title,
            severity=Severity(label) if label in _SEVERITIES else Severity.MEDIUM,
            resource=res,
            fix_type=fix_type_for(control) if control else FixType.UNSUPPORTED,
            observed_at=observed,
            provenance=Provenance(raw_sha256=raw_sha256, schema_name=f"{vendor}-json"),
        )
    except ValidationError as exc:
        raise StageStop(
            "ingest", f"finding could not be normalized: {exc.errors()[0]['msg']}"
        ) from exc


def rule_id_of(item: dict[str, Any], vendor: Vendor) -> str:
    if vendor == "wiz":
        return str(_obj(item.get("sourceRule")).get("id") or "")
    if vendor == "orca":
        return str(_value(_obj(item.get("data")).get("AlertType")) or "")
    return str(item.get("policyId") or _obj(item.get("policy")).get("policyId") or "")


def unmapped_reason(vendor: Vendor, rule_id: str) -> str:
    return (
        f"{NAMES[vendor]} rule {rule_id} has no control mapping; "
        f"add it under detectors.{vendor}.rules"
    )


def control_for(vendor: Vendor, rule_id: str, listed: list[str], rules: Rules | None) -> str | None:
    """The customer's mapping first, else the one supported control the export names."""
    mapped = (rules or {}).get(vendor, {}).get(rule_id)
    if mapped:
        return mapped
    supported = sorted({c for c in listed if _supported(c)})
    if len(supported) > 1 and same_fix(supported):
        supported = supported[:1]
    if len(supported) > 1:
        raise StageStop(
            "ingest",
            f"{NAMES[vendor]} rule {rule_id} names several controls PosturaNet fixes: "
            f"{', '.join(supported)}",
            [f"map it to one under detectors.{vendor}.rules in .posturanet.yml"],
        )
    return supported[0] if supported else None


def _supported(control: str) -> bool:
    from posturanet.outcomes import runbook_for  # outcomes imports ingest

    return fix_type_for(control) is not FixType.UNSUPPORTED or runbook_for(control) is not None


_Fields = tuple[
    str, str, str, str, str, frozenset[str], ResourceRef, datetime | None, list[str]
]  # rule id, alert id, title, severity, status, closed statuses, resource, time, controls


def _wiz(item: dict[str, Any]) -> _Fields:
    rule = _obj(item.get("sourceRule"))
    ent = _obj(item.get("entitySnapshot"))
    listed: list[str] = []
    for sub in rule.get("securitySubCategories") or []:
        framework = _obj(_obj(_obj(sub).get("category")).get("framework")).get("name")
        if _FRAMEWORK.search(str(framework or "")) and (
            m := _CONTROL.match(str(_obj(sub).get("title") or ""))
        ):
            listed.append(m.group(1))
    uid = str(ent.get("providerId") or ent.get("externalId") or ent.get("name") or "")
    res = _resource(
        uid,
        rtype=str(ent.get("nativeType") or ent.get("type") or ""),
        account=ent.get("subscriptionExternalId"),
        region=ent.get("region"),
    )
    return (
        str(rule.get("id") or ""),
        str(item.get("id") or ""),
        str(rule.get("name") or ""),
        str(item.get("severity") or ""),
        str(item.get("status") or ""),
        frozenset({"resolved", "rejected"}),
        res,
        _time(item.get("createdAt")),
        listed,
    )


def _orca(item: dict[str, Any]) -> _Fields:
    data = _obj(item.get("data"))
    inv = _obj(data.get("Inventory"))
    acct = _obj(data.get("CloudAccount"))
    name = str(_value(_obj(acct.get("data")).get("Name")) or acct.get("name") or "")
    res = _resource(
        str(_value(_obj(inv.get("data")).get("Name")) or inv.get("name") or ""),
        rtype=str(inv.get("type") or ""),
        account=name if _ACCOUNT.match(name) else None,  # GCP accounts are named projects
        region=None,
    )
    rule = str(_value(data.get("AlertType")) or "")
    return (
        rule,
        str(_value(data.get("AlertId")) or ""),
        rule,
        str(_value(data.get("RiskLevel")) or ""),
        str(_value(data.get("Status")) or ""),
        frozenset({"closed", "dismissed"}),  # the closed states the sample response shows
        res,
        _time(_value(data.get("CreatedAt"))),
        [],
    )


def _prisma(item: dict[str, Any]) -> _Fields:
    policy = _obj(item.get("policy"))
    r = _obj(item.get("resource"))
    listed: list[str] = []
    for meta in policy.get("complianceMetadata") or []:
        meta = _obj(meta)
        if _FRAMEWORK.search(str(meta.get("standardName") or "")):
            for key in ("requirementId", "sectionId"):
                if m := _CONTROL.match(str(meta.get(key) or "")):
                    listed.append(m.group(1))
    epoch = item.get("alertTime")
    when = (
        datetime.fromtimestamp(epoch / 1000, tz=UTC)
        if isinstance(epoch, int | float) and epoch > 0
        else None
    )
    return (
        rule_id_of(item, "prisma"),
        str(item.get("id") or ""),
        str(policy.get("name") or ""),
        str(policy.get("severity") or ""),
        str(item.get("status") or ""),
        frozenset({"dismissed", "snoozed", "resolved", "pending_resolution"}),
        _resource(
            str(r.get("id") or r.get("name") or ""),
            rtype=str(r.get("resourceType") or ""),
            account=r.get("accountId"),
            region=r.get("regionId"),
        ),
        when,
        listed,
    )


def _resource(uid: str, *, rtype: str, account: Any, region: Any) -> ResourceRef:
    # arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a91f3c2 -> sg-0a91f3c2
    rid = re.split(r"[/:]", uid)[-1] if uid.startswith("arn:") else uid
    parts = uid.split(":")
    if not account and uid.startswith("arn:") and len(parts) > 5:
        account = parts[4]
    return ResourceRef(
        type=rtype or "unknown",
        id=rid,
        arn=uid if uid.startswith("arn:") else None,
        account=str(account) if account else None,
        region=str(region) if region else None,
    )


def _time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _value(field: Any) -> Any:
    """Orca wraps scalar fields as {"value": ...}."""
    return field.get("value") if isinstance(field, dict) else field


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
