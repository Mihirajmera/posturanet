"""S3 public-access benchmark (S3.8 on one bucket): does turning on Block Public Access break
anyone who really needs public access?

Ground truth per requester: `public` is True when the requester only gets in through public
access (anonymous website visitors, a CloudFront origin without origin access control, a
partner admitted by a public bucket policy). Block Public Access cuts exactly those off.
Server access logs are generated from each requester's schedule over the window, so a
requester that only shows up every 120 days is invisible, as in a real account.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from bench.cases import END, WINDOW_DAYS  # noqa: E402
from bench.common import Expect, Result, per_case, summary  # noqa: E402
from fakes import S3Terraform  # noqa: E402
from posturanet.evidence import FileSource  # noqa: E402
from posturanet.models.config import load_config  # noqa: E402
from posturanet.pipeline import Context, run_fix  # noqa: E402
from posturanet.s3fix import contract as s3contract  # noqa: E402

REPO = ROOT / "tests" / "fixtures" / "tf" / "s3"
FINDING = ROOT / "tests" / "fixtures" / "findings" / "s3_assets_public.json"
BUCKET = "acme-assets"
NEW_BPA = "aws_s3_bucket_public_access_block.assets"
APP = "arn:aws:sts::123456789012:assumed-role/app/i-0abc"
PARTNER = "arn:aws:iam::210987654321:role/partner"
CANONICAL = "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"


@dataclass(frozen=True)
class Requester:
    who: str  # "-" anonymous, an ARN, a canonical id, or svc:<service>
    schedule: str  # daily, weekly, every120
    legit: bool
    public: bool  # only gets in through public access
    note: str
    status: int = 200


@dataclass
class S3Case:
    id: str
    title: str
    why: str
    expect: Expect
    requesters: list[Requester]
    policy_public: bool = True
    acl_public: bool = False
    acls_enabled: bool = True
    website: bool = False
    logging: bool = True
    cloudfront: list[dict[str, object]] = field(default_factory=list)
    approve_review: bool = False  # the team approves every needs_review requester


def _days(r: Requester) -> list[str]:
    start = END.date() - timedelta(days=WINDOW_DAYS)
    out = []
    for i in range(WINDOW_DAYS):
        d = start + timedelta(days=i)
        back = (END.date() - d).days
        hit = {"daily": True, "weekly": d.weekday() == 2, "every120": back == 120}[r.schedule]
        if hit:
            out.append(d.isoformat())
    return out


def evidence(case: S3Case) -> dict[str, object]:
    start = END.date() - timedelta(days=WINDOW_DAYS)
    requests = [
        {"requester": r.who, "operation": "REST.GET.OBJECT", "status": r.status, "day": d, "n": 25}
        for r in case.requesters
        for d in _days(r)
    ]
    return {
        "account": "123456789012",
        "window": {"from": start.isoformat(), "to": END.date().isoformat()},
        "buckets": [
            {
                "name": BUCKET,
                "policy_public": case.policy_public,
                "acl_public": case.acl_public,
                "acls_enabled": case.acls_enabled,
                "website": case.website,
                "logging": case.logging,
                "missing_days": [],
                "requests": requests if case.logging else [],
            }
        ],
        "cloudfront": case.cloudfront,
    }


def _score(case: S3Case, tool: str, fixed: bool, note: str = "") -> Result:
    out = Result(tool, "FIXED" if fixed else "STOPPED", case.expect, note=note)
    if fixed:
        out.broken = sorted({r.note for r in case.requesters if r.legit and r.public})
    return out


def posturanet(case: S3Case, work: Path) -> Result:
    repo = work / "repo"
    shutil.copytree(REPO, repo)
    ev = work / "s3.json"
    ev.write_text(json.dumps(evidence(case), indent=1), encoding="utf-8")
    config, _ = load_config(repo)

    def once() -> tuple[str, str]:
        tf = S3Terraform(NEW_BPA, "aws_s3_bucket_public_access_block", create=True)
        ctx = Context(mode="check", evidence=FileSource(ev), terraform=tf, clock=lambda: END)
        record = run_fix(str(FINDING), repo, config, ctx)
        stop = next((s for s in record.stages if s.status.value in ("fail", "unknown")), None)
        return record.result, (stop.summary if stop else record.result)

    result, why = once()
    if result != "VALIDATED" and case.approve_review:
        path = repo / config.contracts.dir / f"{NEW_BPA}.yaml"
        draft = s3contract.load(path)
        if draft is not None and draft.needs_review:
            s3contract.write(
                path,
                draft.model_copy(
                    update={
                        "status": "approved",
                        "must_keep": [*draft.must_keep, *draft.needs_review],
                        "needs_review": [],
                    }
                ),
            )
            result, why = once()
    return _score(case, "PosturaNet", result == "VALIDATED", why)


def block_always(case: S3Case, work: Path) -> Result:
    """Turn on Block Public Access (the shape of a scanner's auto-remediation)."""
    return _score(case, "Block always", True)


def skip_websites(case: S3Case, work: Path) -> Result:
    """Block unless the bucket hosts a website (a common rule-based exception)."""
    if case.website:
        return _score(case, "Skip websites", False, "bucket hosts a website")
    return _score(case, "Skip websites", True)


CONTENDERS: list[Callable[[S3Case, Path], Result]] = [posturanet, block_always, skip_websites]

CASES = [
    S3Case(
        "s3-private-acls-off",
        "Private bucket, ACLs disabled, no access logs",
        "Nothing is public today, so Block Public Access changes no current access.",
        "fix",
        [Requester(APP, "daily", True, False, "in-account app")],
        policy_public=False,
        acls_enabled=False,
        logging=False,
    ),
    S3Case(
        "s3-public-policy-unused",
        "Public policy nobody uses publicly",
        "A leftover public statement; the logs show only the account's own app.",
        "fix",
        [Requester(APP, "daily", True, False, "in-account app")],
    ),
    S3Case(
        "s3-anonymous-scrapers",
        "Public bucket read only by anonymous scrapers",
        "The only anonymous traffic is hostile. Logs can't tell a scraper from a customer.",
        "fix",
        [
            Requester(APP, "daily", True, False, "in-account app"),
            Requester("-", "weekly", False, True, "anonymous scraper"),
        ],
    ),
    S3Case(
        "s3-static-website",
        "Static website with anonymous visitors",
        "The bucket serves a public website; blocking public access takes it down.",
        "stop",
        [Requester("-", "daily", True, True, "website visitors")],
        website=True,
    ),
    S3Case(
        "s3-cloudfront-no-oac",
        "CloudFront origin without origin access control",
        "CloudFront reads the bucket anonymously; blocking public access breaks the CDN.",
        "stop",
        [Requester("-", "daily", True, True, "CloudFront (no OAC)")],
        cloudfront=[{"id": "E3EXAMPLE", "origin": f"{BUCKET}.s3.amazonaws.com", "private": False}],
    ),
    S3Case(
        "s3-cloudfront-oac",
        "CloudFront with origin access control, leftover public policy",
        "CloudFront signs its requests; the public statement is unused.",
        "fix",
        [Requester("svc:cloudfront.amazonaws.com", "daily", True, False, "CloudFront (OAC)")],
        cloudfront=[{"id": "E3EXAMPLE", "origin": f"{BUCKET}.s3.amazonaws.com", "private": True}],
    ),
    S3Case(
        "s3-partner-public-policy",
        "Partner account reads through a public policy",
        "A partner gets in only because the policy is public; blocking it cuts them off.",
        "stop",
        [
            Requester(APP, "daily", True, False, "in-account app"),
            Requester(PARTNER, "weekly", True, True, "partner account"),
        ],
    ),
    S3Case(
        "s3-partner-every-120-days",
        "Partner reads through a public policy every 120 days",
        "Same partner, but its job last ran outside the 90-day log window.",
        "stop",
        [
            Requester(APP, "daily", True, False, "in-account app"),
            Requester(PARTNER, "every120", True, True, "partner account (every 120 days)"),
        ],
    ),
    S3Case(
        "s3-public-no-logs",
        "Public bucket with no access logs",
        "Only the account's app uses it, but nothing records that.",
        "fix",
        [Requester(APP, "daily", True, False, "in-account app")],
        logging=False,
    ),
    S3Case(
        "s3-unknown-requester-approved",
        "Requester without an account, approved by the team",
        "A canonical-id requester PosturaNet can't tie to an account; the team reviews it.",
        "fix",
        [
            Requester(APP, "daily", True, False, "in-account app"),
            Requester(CANONICAL, "weekly", True, False, "legacy ACL grantee"),
        ],
        approve_review=True,
    ),
]


def run() -> dict[str, list[Result]]:
    results: dict[str, list[Result]] = {}
    for case in CASES:
        results[case.id] = []
        for contender in CONTENDERS:
            with tempfile.TemporaryDirectory() as tmp:
                results[case.id].append(contender(case, Path(tmp)))
    return results


def report(results: dict[str, list[Result]]) -> list[str]:
    return [
        "## S3 public access (S3.8)",
        "",
        *summary("Contender", results),
        "",
        *per_case([(c.id, c.title, c.why, c.expect) for c in CASES], results),
    ]
