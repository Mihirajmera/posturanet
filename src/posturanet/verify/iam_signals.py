"""Post-merge IAM signal: AccessDenied on actions the fix removed (FR-32).

Live: CloudTrail `LookupEvents` (management events only; data events such as S3 object reads
need a trail and an export). Offline: `{"denied": [{"principal", "action", "hour", "n"}]}`.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from posturanet.errors import StageStop
from posturanet.evidence.flowlogs import parse_ts

_DENIED = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "Client.UnauthorizedOperation",
    "UnauthorizedAccess",
}
MAX_PAGES = 50


@dataclass
class Denied:
    principal: str  # "role/name" or "user/name"
    action: str  # "s3:PutBucketPolicy"
    hour: datetime
    count: int = 1


class DeniedSource(Protocol):
    def denied(
        self, principals: list[str], services: list[str] | None, start: datetime, end: datetime
    ) -> list[Denied]: ...


class DeniedFile:
    def __init__(self, path: Path) -> None:
        self.path = path

    def denied(
        self, principals: list[str], services: list[str] | None, start: datetime, end: datetime
    ) -> list[Denied]:
        try:
            raw: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
            rows = [
                Denied(
                    principal=str(r["principal"]),
                    action=str(r["action"]),
                    hour=parse_ts(r["hour"]),
                    count=int(r.get("n", 1)),
                )
                for r in raw.get("denied", [])
            ]
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise StageStop("watch", f"cannot read denied file {self.path}: {exc}") from exc
        return [r for r in rows if r.principal in principals and start <= r.hour < end]


def _principal(identity: dict[str, Any]) -> str | None:
    arn = str(((identity.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn", ""))
    arn = arn or str(identity.get("arn", ""))
    for kind in ("role", "user"):
        marker = f":{kind}/"
        if marker in arn:
            return f"{kind}/{arn.split(marker, 1)[1].rsplit('/', 1)[-1]}"
    return None


class CloudTrailDenied:
    def __init__(self, cloudtrail: Any) -> None:
        self.ct = cloudtrail

    def _pages(self, attrs: list[dict[str, str]], start: datetime, end: datetime) -> list[Any]:
        events: list[Any] = []
        token: str | None = None
        for _ in range(MAX_PAGES):
            kw: dict[str, Any] = {"StartTime": start, "EndTime": end, "MaxResults": 50}
            if attrs:
                kw["LookupAttributes"] = attrs
            if token:
                kw["NextToken"] = token
            page = self.ct.lookup_events(**kw)
            events += page.get("Events", [])
            token = page.get("NextToken")
            if not token:
                return events
        raise StageStop(
            "watch",
            f"more than {MAX_PAGES * 50:,} CloudTrail events in the window",
            ["export AccessDenied events for the principals and pass --rejects-file"],
            unknown=True,
        )

    def denied(
        self, principals: list[str], services: list[str] | None, start: datetime, end: datetime
    ) -> list[Denied]:
        queries = (
            [
                [{"AttributeKey": "EventSource", "AttributeValue": f"{s}.amazonaws.com"}]
                for s in services
            ]
            if services
            else [[]]
        )
        out: list[Denied] = []
        for attrs in queries:
            for ev in self._pages(attrs, start, end):
                try:
                    detail = json.loads(ev.get("CloudTrailEvent") or "{}")
                except json.JSONDecodeError:
                    continue
                if detail.get("errorCode") not in _DENIED:
                    continue
                who = _principal(detail.get("userIdentity") or {})
                if who is None or who not in principals:
                    continue
                source = str(detail.get("eventSource", "")).removesuffix(".amazonaws.com")
                out.append(
                    Denied(
                        principal=who,
                        action=f"{source}:{detail.get('eventName', '')}",
                        hour=parse_ts(str(detail.get("eventTime"))),
                    )
                )
        return out


def regressions(rows: list[Denied], removed: list[str], after: list[str]) -> list[str]:
    def covers(patterns: list[str], action: str) -> bool:
        return any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in patterns)

    hits: dict[tuple[str, str], int] = {}
    for r in rows:
        if covers(removed, r.action) and not covers(after, r.action):
            hits[(r.principal, r.action)] = hits.get((r.principal, r.action), 0) + r.count
    return [
        f"{p} → {a} · {n:,} denied (allowed before the fix)" for (p, a), n in sorted(hits.items())
    ]
