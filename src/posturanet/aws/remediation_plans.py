"""Read Security Hub remediation plans and the exposure findings behind them (FR-4c).

Three read-only calls, all on the allowlist: GetRemediationsV2 (the plans, ranked by
priority), ListExposuresByRemediationV2 (the exposures each plan addresses) and
GetFindingsV2 (those exposure findings, whose related events name the control findings).
The result is written to a file that `posturanet findings list|split` and `posturanet fix`
read; nothing here interprets the plan text (NFR-4).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from posturanet.errors import StageStop
from posturanet.ingest.plans import MARKER

PRIORITIES = ("Critical", "High", "Medium", "Low")
_UID_BATCH = 10


def pull_plans(
    securityhub: Any,
    *,
    now: datetime,
    region: str | None,
    max_plans: int = 25,
    priority: str | None = None,
) -> dict[str, Any]:
    """Plans as a PosturaNet plans document. `securityhub` is a ReadOnlyClient."""
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:  # pragma: no cover - boto3 is a hard dependency
        raise StageStop("ingest", "boto3 is not installed") from exc
    try:
        plans = _plans(securityhub, max_plans, priority)
        for plan in plans:
            exposures = _exposures(securityhub, str(plan["TargetUid"]))
            plan["Exposures"] = exposures
            plan["ExposureFindings"] = _findings(
                securityhub, [str(e["MetadataUid"]) for e in exposures if e.get("MetadataUid")]
            )
    except (BotoCoreError, ClientError) as exc:
        raise StageStop(
            "ingest",
            "could not read Security Hub remediation plans",
            [
                "check the role allows securityhub:GetRemediationsV2, "
                "securityhub:ListExposuresByRemediationV2 and securityhub:GetFindingsV2",
                "remediation plans need Security Hub (not only Security Hub CSPM) in this Region",
            ],
            why=str(exc),
        ) from exc
    return {
        MARKER: "1",
        "Source": "securityhub GetRemediationsV2 + ListExposuresByRemediationV2 + GetFindingsV2",
        "PulledAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Region": region,
        "Plans": plans,
    }


def _plans(client: Any, max_plans: int, priority: str | None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"ShowGuidance": True, "GuidanceFormat": "Terraform"}
    if priority:
        params["Filters"] = {
            "CompositeFilters": [
                {"StringFilters": [{"FieldName": "Priority", "Filter": {"Value": priority}}]}
            ]
        }
    out: list[dict[str, Any]] = []
    token: str | None = None
    while len(out) < max_plans:
        page = client.get_remediations_v2(
            **params,
            MaxResults=min(100, max_plans - len(out)),
            **({"NextToken": token} if token else {}),
        )
        out += [_plain(i) for i in page.get("Items") or []]
        token = page.get("NextToken")
        if not token:
            break
    return out[:max_plans]


def _exposures(client: Any, target_uid: str) -> list[dict[str, Any]]:
    page = client.list_exposures_by_remediation_v2(TargetUid=target_uid, MaxResults=100)
    return [_plain(i) for i in page.get("Items") or []]


def _findings(client: Any, uids: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for start in range(0, len(uids), _UID_BATCH):
        batch = uids[start : start + _UID_BATCH]
        page = client.get_findings_v2(
            Filters={
                "CompositeFilters": [
                    {
                        "StringFilters": [
                            {
                                "FieldName": "metadata.uid",
                                "Filter": {"Value": uid, "Comparison": "EQUALS"},
                            }
                            for uid in batch
                        ],
                        "Operator": "OR",
                    }
                ]
            },
            MaxResults=100,
        )
        out += [_plain(f) for f in page.get("Findings") or []]
    return out


def _plain(value: Any) -> Any:
    """JSON-ready copy: boto3 returns datetimes for timestamp fields."""
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items() if k != "ResponseMetadata"}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return value
