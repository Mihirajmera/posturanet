"""Evidence for S3 public-access fixes (FR-50, architecture doc 14.2).

Turning on all four Block Public Access settings changes access only for a bucket that is
public today: a public policy, a public ACL, or object ACLs that might be public. For those,
the server access logs over the window must show no anonymous use, no cross-account use that
relies on the public policy, and no CloudFront origin or website that needs public reads.
Any such use stops the fix (NFR-1); the people who own it decide, not PosturaNet.

Facts come from an evidence file (offline) or from read-only S3 and CloudFront calls.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from posturanet.errors import StageStop
from posturanet.evidence.confidence import confidence_for
from posturanet.models import Confidence
from posturanet.models.s3 import (
    BucketEvidence,
    CloudFrontOrigin,
    Exposure,
    RequesterKind,
    S3Evidence,
    S3Use,
)

_CANONICAL_ID = re.compile(r"^[0-9a-f]{64}$")
_TOKENS = re.compile(r'\[[^\]]*\]|"[^"]*"|\S+')
_LOG_KEY_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})-\d{2}-\d{2}-\d{2}-[0-9A-F]+$")
MAX_LOG_OBJECTS = 20_000


@dataclass
class LogRow:
    requester: str
    operation: str
    status: int
    day: date
    count: int = 1
    bucket: str = ""


@dataclass
class BucketFacts:
    name: str
    exposure: Exposure
    logging: bool
    rows: list[LogRow] = field(default_factory=list)
    log_days: set[date] = field(default_factory=set)


@dataclass
class S3Facts:
    account: str | None
    start: date
    end: date  # exclusive
    buckets: list[BucketFacts]
    cloudfront: list[CloudFrontOrigin] = field(default_factory=list)


class S3Source(Protocol):
    source: str

    def bucket(self, name: str, start: date, end: date) -> S3Facts: ...

    def account(self, start: date, end: date) -> S3Facts: ...


# --- analysis (pure)


def classify(requester: str, account: str | None) -> RequesterKind:
    if requester == "-":
        return "anonymous"
    if requester.startswith("svc:") or requester.endswith(".amazonaws.com"):
        return "service"
    if requester.startswith("arn:"):
        parts = requester.split(":")
        owner = parts[4] if len(parts) > 4 else ""
        if not owner or account is None:
            return "unknown"
        return "in_account" if owner == account else "cross_account"
    return "unknown"  # canonical ids and anything else can't be tied to an account


def _uses(rows: Iterable[LogRow], account: str | None) -> list[S3Use]:
    agg: dict[str, tuple[set[str], int, date]] = {}
    for r in rows:
        if r.status >= 400:
            continue  # refused already; the fix can't break what doesn't work today
        ops, n, last = agg.get(r.requester, (set(), 0, r.day))
        ops.add(r.operation)
        agg[r.requester] = (ops, n + r.count, max(last, r.day))
    return [
        S3Use(
            requester=req,
            kind=classify(req, account),
            operations=sorted(ops),
            count=n,
            last_seen=last,
        )
        for req, (ops, n, last) in sorted(agg.items())
    ]


def _origin_for(origin: CloudFrontOrigin, bucket: str) -> bool:
    d = origin.domain.lower()
    return d.startswith(f"{bucket.lower()}.s3.") or d.startswith(f"{bucket.lower()}.s3-website")


def analyze(
    facts: S3Facts, *, scope: str, source: str, reviewed: frozenset[str] = frozenset()
) -> S3Evidence:
    """`reviewed`: requesters a human approved in the contract (never anonymous use)."""
    blockers: list[str] = []
    out: list[BucketEvidence] = []
    log_needed = [b for b in facts.buckets if b.exposure.needs_logs]
    for b in facts.buckets:
        ev = BucketEvidence(bucket=b.name, exposure=b.exposure, logging=b.logging)
        ev.cloudfront = [o for o in facts.cloudfront if _origin_for(o, b.name)]
        if scope == "account":
            # The account setting would apply to every bucket at once: each must be private
            # today, with ACLs disabled, or be fixed (with its own evidence) first.
            if b.exposure.needs_logs:
                why = _exposure_text(b.exposure)
                blockers.append(f"{b.name} is {why}; fix that bucket first")
            out.append(ev)
            continue
        if b.exposure.needs_logs:
            for use in _uses(b.rows, facts.account):
                public_path = b.exposure.public
                if use.kind == "anonymous" or use.kind == "cross_account" and public_path:
                    ev.breaks.append(use)
                elif use.kind == "unknown" and use.requester not in reviewed:
                    ev.needs_review.append(use)
                else:
                    ev.keeps.append(use)
            for use in ev.breaks:
                who = "anonymous requests" if use.kind == "anonymous" else use.requester
                blockers.append(
                    f"{who}: {use.count:,} successful request(s) to {b.name} "
                    f"({', '.join(use.operations[:3])}), last {use.last_seen}"
                )
            for use in ev.needs_review:
                blockers.append(
                    f"{use.requester[:16]}…: requester can't be tied to an account "
                    f"({use.count:,} requests); confirm it in the contract"
                )
            if b.exposure.website and b.exposure.public:
                blockers.append(f"{b.name} serves a static website, which needs public reads")
            for o in ev.cloudfront:
                if not o.private and b.exposure.public:
                    blockers.append(
                        f"CloudFront {o.distribution} reads {b.name} without origin access "
                        "control; it would get 403s"
                    )
        out.append(ev)

    days = (facts.end - facts.start).days
    if scope == "account" or not log_needed:
        basis = (
            "no bucket in the account is public today and ACLs are disabled"
            if scope == "account"
            else "the bucket isn't public today and ACLs are disabled"
        )
        if blockers:
            basis = "some buckets are public today"
        conf = Confidence.NONE if blockers else Confidence.HIGH
        return S3Evidence(
            scope="account" if scope == "account" else "bucket",
            source="s3_config" if source != "s3_evidence_file" else source,
            basis=basis,
            window_days=0,
            coverage_ratio=1.0,
            buckets=out,
            blockers=blockers,
            confidence=conf,
        )

    b = log_needed[0]
    ratio, gap = _day_coverage(facts.start, facts.end, b.log_days)
    conf = confidence_for(days, ratio, gap * 24) if b.logging else Confidence.NONE
    checked = "access logs checked for public use" if b.logging else "it has no access logs"
    return S3Evidence(
        scope="bucket",
        source=source,
        basis=f"the bucket is {_exposure_text(b.exposure)}; {checked}",
        window_days=days,
        coverage_ratio=ratio,
        buckets=out,
        blockers=blockers,
        confidence=conf,
    )


def _exposure_text(e: Exposure) -> str:
    if e.policy_public:
        return "public through its bucket policy"
    if e.acl_public:
        return "public through its ACL"
    return "using ACLs (objects may be public)"


def _day_coverage(start: date, end: date, present: set[date]) -> tuple[float, int]:
    total = (end - start).days
    if total <= 0:
        return 0.0, 0
    hit = gap = max_gap = 0
    for i in range(total):
        if start + timedelta(days=i) in present:
            hit += 1
            gap = 0
        else:
            gap += 1
            max_gap = max(max_gap, gap)
    return round(hit / total, 4), max_gap


# --- server access log parsing


def parse_log_line(line: str) -> LogRow | None:
    """One S3 server access log record -> LogRow; None for lines that don't parse."""
    t = _TOKENS.findall(line)
    if len(t) < 10 or not t[2].startswith("["):
        return None
    try:
        when = datetime.strptime(t[2][1:-1], "%d/%b/%Y:%H:%M:%S %z")
        status = int(t[9]) if t[9].isdigit() else 0
    except ValueError:
        return None
    return LogRow(
        requester=t[4],
        operation=t[6],
        status=status,
        day=when.astimezone(UTC).date(),
        bucket=t[1],
    )


# --- sources


def _parse_day(value: Any) -> date:
    return date.fromisoformat(str(value)[:10])


class FileS3Source:
    """JSON export (see docs/02 §14.2):
    `{"account", "window": {"from", "to"}, "buckets": [{"name", "policy_public", "acl_public",
      "acls_enabled", "website", "logging", "missing_days"?, "requests": [{"requester",
      "operation", "status", "day", "n"}]}], "cloudfront": [{"id", "origin", "private"}]}`

    Without `missing_days`, coverage counts only days with requests (conservative).
    """

    source = "s3_evidence_file"

    def __init__(self, path: Path) -> None:
        self.path = path

    def _load(self) -> S3Facts:
        try:
            raw: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StageStop("evidence", f"cannot read evidence file {self.path}: {exc}") from exc
        try:
            start, end = _parse_day(raw["window"]["from"]), _parse_day(raw["window"]["to"])
            buckets = []
            for b in raw.get("buckets", []):
                rows = [
                    LogRow(
                        requester=str(r["requester"]),
                        operation=str(r.get("operation", "")),
                        status=int(r.get("status", 200)),
                        day=_parse_day(r["day"]),
                        count=int(r.get("n", 1)),
                    )
                    for r in b.get("requests", [])
                ]
                if "missing_days" in b:
                    missing = {_parse_day(d) for d in b["missing_days"]}
                    days = {
                        start + timedelta(days=i)
                        for i in range((end - start).days)
                        if start + timedelta(days=i) not in missing
                    }
                else:
                    days = {r.day for r in rows}
                buckets.append(
                    BucketFacts(
                        name=str(b["name"]),
                        exposure=Exposure(
                            policy_public=bool(b["policy_public"]),
                            acl_public=bool(b["acl_public"]),
                            acls_enabled=bool(b["acls_enabled"]),
                            website=bool(b.get("website", False)),
                        ),
                        logging=bool(b.get("logging", False)),
                        rows=rows,
                        log_days=days if b.get("logging") else set(),
                    )
                )
            cloudfront = [
                CloudFrontOrigin(
                    distribution=str(o["id"]), domain=str(o["origin"]), private=bool(o["private"])
                )
                for o in raw.get("cloudfront", [])
            ]
        except (KeyError, TypeError, ValueError) as exc:
            raise StageStop(
                "evidence", f"evidence file {self.path.name} is not an S3 evidence export: {exc}"
            ) from exc
        account = str(raw["account"]) if raw.get("account") else None
        return S3Facts(account, start, end, buckets, cloudfront)

    def bucket(self, name: str, start: date, end: date) -> S3Facts:
        facts = self._load()
        facts.buckets = [b for b in facts.buckets if b.name == name]
        if not facts.buckets:
            raise StageStop("evidence", f"evidence file has no entry for bucket {name}")
        return facts

    def account(self, start: date, end: date) -> S3Facts:
        return self._load()


_PUBLIC_GRANTEES = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


class LiveS3Source:
    """Read-only S3 and CloudFront calls through `aws/readonly.py`."""

    source = "s3_access_logs"

    def __init__(self, s3: Any, cloudfront: Any, account: str | None) -> None:
        self.s3, self.cf, self.account_id = s3, cloudfront, account

    def _err(self, exc: Exception) -> str:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        return str(code or type(exc).__name__)

    def _exposure(self, name: str) -> Exposure:
        try:
            status = self.s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
        except Exception as exc:
            if self._err(exc) != "NoSuchBucketPolicy":
                raise StageStop(
                    "evidence", f"can't read {name} policy status: {self._err(exc)}"
                ) from exc
            status = False
        try:
            grants = self.s3.get_bucket_acl(Bucket=name).get("Grants", [])
        except Exception as exc:
            raise StageStop("evidence", f"can't read {name} ACL: {self._err(exc)}") from exc
        acl_public = any(g.get("Grantee", {}).get("URI") in _PUBLIC_GRANTEES for g in grants)
        try:
            rules = self.s3.get_bucket_ownership_controls(Bucket=name)["OwnershipControls"]
            enforced = any(
                r.get("ObjectOwnership") == "BucketOwnerEnforced" for r in rules["Rules"]
            )
        except Exception as exc:
            if self._err(exc) != "OwnershipControlsNotFoundError":
                raise StageStop(
                    "evidence", f"can't read {name} ownership: {self._err(exc)}"
                ) from exc
            enforced = False
        try:
            self.s3.get_bucket_website(Bucket=name)
            website = True
        except Exception as exc:
            if self._err(exc) != "NoSuchWebsiteConfiguration":
                raise StageStop("evidence", f"can't read {name} website: {self._err(exc)}") from exc
            website = False
        return Exposure(
            policy_public=bool(status),
            acl_public=acl_public,
            acls_enabled=not enforced,
            website=website,
        )

    def _cloudfront(self) -> list[CloudFrontOrigin]:
        out: list[CloudFrontOrigin] = []
        marker: str | None = None
        while True:
            kw = {"Marker": marker} if marker else {}
            page = self.cf.list_distributions(**kw).get("DistributionList", {})
            for d in page.get("Items", []) or []:
                for o in d.get("Origins", {}).get("Items", []) or []:
                    oai = (o.get("S3OriginConfig") or {}).get("OriginAccessIdentity")
                    out.append(
                        CloudFrontOrigin(
                            distribution=str(d["Id"]),
                            domain=str(o.get("DomainName", "")),
                            private=bool(o.get("OriginAccessControlId") or oai),
                        )
                    )
            if not page.get("IsTruncated"):
                return out
            marker = page.get("NextMarker")

    def _logs(self, name: str, start: date, end: date) -> tuple[bool, list[LogRow], set[date]]:
        try:
            cfg = self.s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
        except Exception as exc:
            raise StageStop("evidence", f"can't read {name} logging: {self._err(exc)}") from exc
        if not cfg:
            return False, [], set()
        if cfg.get("TargetObjectKeyFormat", {}).get("PartitionedPrefix") is not None:
            raise StageStop(
                "evidence",
                f"{name} uses partitioned access-log keys; reading them live isn't supported yet",
                ["export the logs with Athena and pass --evidence-file (docs/02 §14.2)"],
            )
        target, prefix = cfg["TargetBucket"], cfg.get("TargetPrefix", "")
        keys: list[str] = []
        token: str | None = None
        past_end = False
        while not past_end:
            kw: dict[str, Any] = {"Bucket": target, "Prefix": prefix}
            if token:
                kw["ContinuationToken"] = token
            else:
                kw["StartAfter"] = f"{prefix}{start:%Y-%m-%d}"
            page = self.s3.list_objects_v2(**kw)
            for obj in page.get("Contents", []):
                m = _LOG_KEY_DATE.search(obj["Key"])
                if m and date(int(m[1]), int(m[2]), int(m[3])) >= end:
                    past_end = True
                    break
                keys.append(obj["Key"])
            if len(keys) > MAX_LOG_OBJECTS:
                raise StageStop(
                    "evidence",
                    f"{name} has more than {MAX_LOG_OBJECTS:,} log objects in the window",
                    ["export the logs with Athena and pass --evidence-file (docs/02 §14.2)"],
                )
            if not page.get("IsTruncated"):
                break
            token = page.get("NextContinuationToken")
        rows: list[LogRow] = []
        days: set[date] = set()
        for key in keys:
            body = (
                self.s3.get_object(Bucket=target, Key=key)["Body"].read().decode("utf-8", "replace")
            )
            for line in body.splitlines():
                row = parse_log_line(line)
                if row is not None and row.bucket == name and start <= row.day < end:
                    rows.append(row)
                    days.add(row.day)
            m = _LOG_KEY_DATE.search(key)
            if m:
                days.add(date(int(m[1]), int(m[2]), int(m[3])))
        return True, rows, days

    def bucket(self, name: str, start: date, end: date) -> S3Facts:
        exposure = self._exposure(name)
        logging, rows, days = False, list[LogRow](), set[date]()
        if exposure.needs_logs:
            logging, rows, days = self._logs(name, start, end)
        facts = BucketFacts(name, exposure, logging, rows, days)
        cloudfront = self._cloudfront() if exposure.public else []
        return S3Facts(self.account_id, start, end, [facts], cloudfront)

    def account(self, start: date, end: date) -> S3Facts:
        names = sorted(b["Name"] for b in self.s3.list_buckets().get("Buckets", []))
        buckets = [BucketFacts(n, self._exposure(n), logging=False) for n in names]
        return S3Facts(self.account_id, start, end, buckets, [])
