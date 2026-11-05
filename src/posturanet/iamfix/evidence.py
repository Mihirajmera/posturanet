"""IAM usage evidence: action-level last-accessed data for one policy (FR-16, FR-51).

`GenerateServiceLastAccessedDetails` on the policy ARN, `ACTION_LEVEL`: for every service the
policy allows, when any attached principal last used it, and for services IAM tracks at
action level, when each tracked action was last used. Any use in IAM's tracking period
(about 400 days) counts, which errs toward keeping actions.

Read-only, through `aws/readonly.py`. Offline: an evidence file in the same shape.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Protocol

from posturanet.errors import StageStop
from posturanet.iamfix.shrink import ServiceUse
from posturanet.models import Confidence
from posturanet.models.iam import IamEvidence, ServiceAccess, TrackedUse

_MAX_POLLS = 60


class IamSource(Protocol):
    source: str

    def policy(self, policy_arn: str, today: date) -> IamEvidence: ...


def confidence_for_age(age_days: int, principals: int) -> Confidence:
    """Last-accessed data only covers time the policy existed and was attached."""
    if principals == 0:
        return Confidence.NONE
    if age_days >= 60:
        return Confidence.HIGH
    if age_days >= 14:
        return Confidence.MEDIUM
    return Confidence.LOW


def usage(ev: IamEvidence) -> dict[str, ServiceUse]:
    return {
        s.namespace.lower(): ServiceUse(
            namespace=s.namespace.lower(),
            accessed=s.last_accessed is not None,
            action_level=s.action_level,
            actions={a.action for a in s.actions if a.last_seen is not None},
        )
        for s in ev.services
    }


def _day(value: Any) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).date()
    return date.fromisoformat(str(value)[:10])


def _evidence(
    arn: str,
    source: str,
    created: date | None,
    principals: list[str],
    services: list[ServiceAccess],
    today: date,
) -> IamEvidence:
    age = (today - created).days if created else 0
    return IamEvidence(
        policy_arn=arn,
        source=source,
        created=created,
        age_days=max(age, 0),
        principals=sorted(principals),
        services=sorted(services, key=lambda s: s.namespace),
        confidence=confidence_for_age(age, len(principals)),
    )


class FileIamSource:
    """JSON export:
    `{"policy_arn", "created", "principals": [...], "services": [{"namespace",
      "last_accessed", "action_level", "actions": [{"name", "last_accessed"}]}]}`
    """

    source = "iam_evidence_file"

    def __init__(self, path: Path) -> None:
        self.path = path

    def policy(self, policy_arn: str, today: date) -> IamEvidence:
        try:
            raw: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
            if raw.get("policy_arn") not in (None, policy_arn):
                raise StageStop(
                    "evidence", f"evidence file is for {raw['policy_arn']}, not {policy_arn}"
                )
            services = [
                ServiceAccess(
                    namespace=str(s["namespace"]).lower(),
                    last_accessed=_day(s.get("last_accessed")),
                    action_level=bool(s.get("action_level", False)),
                    actions=[
                        TrackedUse(
                            action=f"{str(s['namespace']).lower()}:{a['name']}",
                            last_seen=_day(a.get("last_accessed")),
                        )
                        for a in s.get("actions", [])
                    ],
                )
                for s in raw.get("services", [])
            ]
            principals = [str(p) for p in raw.get("principals", [])]
            created = _day(raw.get("created"))
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise StageStop(
                "evidence", f"evidence file {self.path.name} is not an IAM evidence export: {exc}"
            ) from exc
        return _evidence(policy_arn, self.source, created, principals, services, today)


class LiveIamSource:
    source = "iam_last_accessed"

    def __init__(self, iam: Any, sleep: Callable[[float], None] = time.sleep) -> None:
        self.iam, self.sleep = iam, sleep

    def _principals(self, arn: str) -> list[str]:
        out: list[str] = []
        marker: str | None = None
        while True:
            kw: dict[str, Any] = {"PolicyArn": arn}
            if marker:
                kw["Marker"] = marker
            page = self.iam.list_entities_for_policy(**kw)
            out += [f"role/{r['RoleName']}" for r in page.get("PolicyRoles", [])]
            out += [f"user/{u['UserName']}" for u in page.get("PolicyUsers", [])]
            out += [f"group/{g['GroupName']}" for g in page.get("PolicyGroups", [])]
            if not page.get("IsTruncated"):
                return out
            marker = page.get("Marker")

    def _report(self, arn: str) -> list[dict[str, Any]]:
        job = self.iam.generate_service_last_accessed_details(Arn=arn, Granularity="ACTION_LEVEL")[
            "JobId"
        ]
        services: list[dict[str, Any]] = []
        marker: str | None = None
        for _ in range(_MAX_POLLS):
            kw: dict[str, Any] = {"JobId": job}
            if marker:
                kw["Marker"] = marker
            page = self.iam.get_service_last_accessed_details(**kw)
            status = page.get("JobStatus")
            if status == "FAILED":
                raise StageStop("evidence", "IAM last-accessed job failed", unknown=True)
            if status != "COMPLETED":
                self.sleep(2.0)
                continue
            services += page.get("ServicesLastAccessed", [])
            if not page.get("IsTruncated"):
                return services
            marker = page.get("Marker")
        raise StageStop("evidence", "IAM last-accessed job didn't finish in time", unknown=True)

    def policy(self, policy_arn: str, today: date) -> IamEvidence:
        created = _day(self.iam.get_policy(PolicyArn=policy_arn)["Policy"].get("CreateDate"))
        principals = self._principals(policy_arn)
        services = []
        for s in self._report(policy_arn):
            ns = str(s["ServiceNamespace"]).lower()
            tracked = s.get("TrackedActionsLastAccessed")
            services.append(
                ServiceAccess(
                    namespace=ns,
                    last_accessed=_day(s.get("LastAuthenticated")),
                    action_level=tracked is not None,
                    actions=[
                        TrackedUse(
                            action=f"{ns}:{a['ActionName']}",
                            last_seen=_day(a.get("LastAccessedTime")),
                        )
                        for a in tracked or []
                    ],
                )
            )
        return _evidence(policy_arn, self.source, created, principals, services, today)
