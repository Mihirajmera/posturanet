"""S3 public-access fixes (FR-50): evidence, contract, fix, validation, PR and verify."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from fakes import FakeGitHub, S3Terraform
from posturanet.aws.readonly import ReadOnlyClient, iam_action, is_allowed
from posturanet.deliver import GitHub
from posturanet.deliver.idempotency import spec_in
from posturanet.evidence import FileSource
from posturanet.models import StageStatus
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix
from posturanet.s3fix import FLAG_NAMES
from posturanet.s3fix import contract as s3contract
from posturanet.s3fix.evidence import LiveS3Source, classify, parse_log_line
from posturanet.validate.plan_scope import check_scope
from posturanet.verify import VerifyContext, run_verify

FIXTURES = Path(__file__).parent.parent / "fixtures"
ASSETS = str(FIXTURES / "findings" / "s3_assets_public.json")
REPORTS = str(FIXTURES / "findings" / "s3_reports_public.json")
ACCOUNT = str(FIXTURES / "findings" / "s3_account_bpa.json")
NEW_BPA = "aws_s3_bucket_public_access_block.assets"
CONTRACT = f"posturanet/contracts/{NEW_BPA}.yaml"


def _clock() -> datetime:
    return datetime(2026, 10, 30, 6, tzinfo=UTC)


def _ev(name: str) -> FileSource:
    return FileSource(FIXTURES / "s3" / name)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    out = tmp_path / "repo"
    shutil.copytree(FIXTURES / "tf" / "s3", out)
    return out


def _status(record: Any) -> dict[str, StageStatus]:
    return {s.name: s.status for s in record.stages}


# --- evidence


def test_private_bucket_needs_no_logs_and_adds_a_block(repo: Path) -> None:
    config, _ = load_config(repo)
    before = (repo / "main.tf").read_bytes()
    ctx = Context(mode="dry-run", evidence=_ev("private.json"), clock=_clock)
    record = run_fix(ASSETS, repo, config, ctx)
    assert record.result == "DRY RUN", record.stages
    assert record.s3_evidence is not None
    assert record.s3_evidence.source == "s3_evidence_file"
    assert "isn't public today" in record.s3_evidence.basis
    assert record.diff is not None
    assert record.diff.summary == f"add {NEW_BPA} with all four settings on"
    new = record.diff.files[0].new_content
    assert 'resource "aws_s3_bucket_public_access_block" "assets" {' in new
    assert "bucket = aws_s3_bucket.assets.id" in new
    assert (repo / "main.tf").read_bytes() == before
    assert not (repo / CONTRACT).exists()


def test_public_bucket_without_public_use_passes(repo: Path) -> None:
    config, _ = load_config(repo)
    ctx = Context(mode="dry-run", evidence=_ev("public_unused.json"), clock=_clock)
    record = run_fix(ASSETS, repo, config, ctx)
    assert record.result == "DRY RUN", record.stages
    ev = record.s3_evidence
    assert ev is not None and ev.confidence.value == "high" and ev.window_days == 90
    assert not ev.blockers
    keeps = ev.buckets[0].keeps
    assert [u.kind for u in keeps] == ["in_account"]  # the denied anonymous GETs don't count
    assert "risk medium" in record.result_detail


def test_public_use_stops_the_fix(repo: Path) -> None:
    config, _ = load_config(repo)
    ctx = Context(mode="check", evidence=_ev("public_used.json"), clock=_clock)
    record = run_fix(ASSETS, repo, config, ctx)
    assert record.result == "STOPPED"
    assert record.exit_code == 3
    assert _status(record)["evidence"] is StageStatus.FAIL
    blockers = record.s3_evidence.blockers if record.s3_evidence else []
    assert any(b.startswith("anonymous requests: 1,250") for b in blockers), blockers
    assert any("210987654321" in b for b in blockers)
    assert any("CloudFront E3EXAMPLE" in b for b in blockers)
    assert record.diff is None
    assert (repo / CONTRACT).is_file(), "the draft contract is written for review"


def test_unknown_requester_needs_review_until_approved(repo: Path) -> None:
    config, _ = load_config(repo)
    ctx = Context(mode="check", evidence=_ev("unknown_requester.json"), clock=_clock)
    stopped = run_fix(ASSETS, repo, config, ctx)
    assert stopped.result == "STOPPED"
    assert "can't be tied to an account" in stopped.stages[-1].summary or any(
        "can't be tied" in d for s in stopped.stages for d in s.details
    )
    draft = s3contract.load(repo / CONTRACT)
    assert draft is not None and len(draft.needs_review) == 1

    approved = draft.model_copy(
        update={
            "status": "approved",
            "must_keep": [
                *draft.must_keep,
                draft.needs_review[0].model_copy(update={"owner": "@data"}),
            ],
            "needs_review": [],
        }
    )
    s3contract.write(repo / CONTRACT, approved)
    tf = S3Terraform(NEW_BPA, "aws_s3_bucket_public_access_block", create=True)
    record = run_fix(
        ASSETS,
        repo,
        config,
        Context(mode="check", evidence=ctx.evidence, terraform=tf, clock=_clock),
    )
    assert record.result == "VALIDATED", record.stages
    assert "approved contract" in next(s.summary for s in record.stages if s.name == "contract")


def test_no_access_logs_on_a_public_bucket_stops(repo: Path, tmp_path: Path) -> None:
    doc = json.loads((FIXTURES / "s3" / "public_unused.json").read_text(encoding="utf-8"))
    doc["buckets"][0]["logging"] = False
    path = tmp_path / "nologs.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    config, _ = load_config(repo)
    record = run_fix(
        ASSETS, repo, config, Context(mode="dry-run", evidence=FileSource(path), clock=_clock)
    )
    assert record.result == "STOPPED" and record.exit_code == 3
    evidence = next(s for s in record.stages if s.name == "evidence")
    assert evidence.status is StageStatus.UNKNOWN
    assert "it has no access logs · confidence none" in evidence.summary
    assert record.why == "PosturaNet never changes a resource without usage evidence"


# --- fix + validation


def test_check_mode_validates_a_new_block(repo: Path) -> None:
    config, _ = load_config(repo)
    tf = S3Terraform(NEW_BPA, "aws_s3_bucket_public_access_block", create=True)
    ctx = Context(mode="check", evidence=_ev("private.json"), terraform=tf, clock=_clock)
    record = run_fix(ASSETS, repo, config, ctx)
    assert record.result == "VALIDATED", record.stages
    assert record.validation is not None
    checks = {c.id: (c.result.value, c.detail) for c in record.validation.checks if c.required}
    assert {k: v[0] for k, v in checks.items()} == {
        "guardrails": "pass",
        "recheck": "pass",
        "fmt": "pass",
        "validate": "pass",
        "plan_scope": "pass",
        "plan_matches": "pass",
    }
    assert checks["plan_scope"][1].startswith("0 to change, 1 to add")
    assert (repo / CONTRACT).is_file()


def test_plan_that_changes_the_bucket_too_fails(repo: Path) -> None:
    config, _ = load_config(repo)
    extra = [
        {
            "address": "aws_s3_bucket.assets",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "change": {"actions": ["update"], "before": {}, "after": {}},
        }
    ]
    tf = S3Terraform(NEW_BPA, "aws_s3_bucket_public_access_block", create=True, extra=extra)
    ctx = Context(mode="check", evidence=_ev("private.json"), terraform=tf, clock=_clock)
    record = run_fix(ASSETS, repo, config, ctx)
    assert record.result == "STOPPED" and record.exit_code == 4
    assert "plan also changes aws_s3_bucket.assets" in record.stages[-2].summary or any(
        "plan also changes" in s.summary for s in record.stages
    )


def test_existing_block_is_updated_in_place(repo: Path) -> None:
    config, _ = load_config(repo)
    tf = S3Terraform(
        "aws_s3_bucket_public_access_block.reports",
        "aws_s3_bucket_public_access_block",
        create=False,
    )
    ctx = Context(mode="check", evidence=_ev("reports_private.json"), terraform=tf, clock=_clock)
    record = run_fix(REPORTS, repo, config, ctx)
    assert record.result == "VALIDATED", record.stages
    assert record.diff is not None
    assert record.diff.summary == "block_public_policy = true; restrict_public_buckets = true"
    fix = next(s for s in record.stages if s.name == "fix")
    assert fix.details == [
        "already set: block_public_acls = true",
        "already set: ignore_public_acls = true",
    ]


def test_account_setting_adds_a_file_when_no_bucket_is_public(repo: Path) -> None:
    config, _ = load_config(repo)
    tf = S3Terraform(
        "aws_s3_account_public_access_block.this", "aws_s3_account_public_access_block", create=True
    )
    ctx = Context(mode="check", evidence=_ev("account_clean.json"), terraform=tf, clock=_clock)
    record = run_fix(ACCOUNT, repo, config, ctx)
    assert record.result == "VALIDATED", record.stages
    assert record.diff is not None
    assert record.diff.files[0].path == "s3_account_public_access_block.tf"
    assert "the account setting also applies to buckets created later" in record.unknowns


def test_account_setting_stops_while_a_bucket_is_public(repo: Path) -> None:
    config, _ = load_config(repo)
    ctx = Context(mode="dry-run", evidence=_ev("account_public.json"), clock=_clock)
    record = run_fix(ACCOUNT, repo, config, ctx)
    assert record.result == "STOPPED"
    assert "acme-assets is public through its bucket policy; fix that bucket first" in (
        record.why or ""
    ) or any("fix that bucket first" in d for s in record.stages for d in s.details)


def test_s3_19_is_not_fixed(repo: Path, tmp_path: Path) -> None:
    doc = json.loads(Path(ASSETS).read_text(encoding="utf-8"))
    doc["Findings"][0]["Compliance"]["SecurityControlId"] = "S3.19"
    doc["Findings"][0]["GeneratorId"] = "security-control/S3.19"
    path = tmp_path / "s3_19.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    config, _ = load_config(repo)
    record = run_fix(str(path), repo, config, Context(mode="dry-run"))
    assert record.result == "STOPPED"
    assert "forces resource replacement" in record.stages[0].summary


def test_dry_run_without_evidence_stops_after_locate(repo: Path) -> None:
    config, _ = load_config(repo)
    record = run_fix(ASSETS, repo, config, Context(mode="dry-run"))
    assert record.result == "DRY RUN"
    assert _status(record)["evidence"] is StageStatus.SKIPPED
    locate = next(s for s in record.stages if s.name == "locate")
    assert f"public access block {NEW_BPA} (new, in main.tf)" in locate.details


# --- deliver + verify


def test_open_pr_then_verify_confirms(repo: Path, tmp_path: Path) -> None:
    config, _ = load_config(repo)
    fake = FakeGitHub({"main.tf": (repo / "main.tf").read_text(encoding="utf-8")})
    gh = GitHub("t", "acme/infra", fake.client())
    tf = S3Terraform(NEW_BPA, "aws_s3_bucket_public_access_block", create=True)
    ctx = Context(
        mode="open-pr", evidence=_ev("public_unused.json"), terraform=tf, github=gh, clock=_clock
    )
    record = run_fix(ASSETS, repo, config, ctx)
    assert record.result == "OPENED", record.stages
    pr = fake.prs[0]
    assert pr["title"] == "🔒 PosturaNet: block public access on acme-assets (S3.8)"
    assert "### Evidence" in pr["body"] and "keeps working" in pr["body"]
    assert "guarantee" not in pr["body"].replace("not a guarantee", "")
    spec = spec_in(pr["body"])
    assert spec is not None and spec.fix_type == "s3_public" and spec.address == NEW_BPA
    branch = pr["head"]["ref"]
    assert branch.startswith("posturanet/s3/s3-8-acme-assets-")
    assert (branch, CONTRACT) in fake.files

    fake.merge(412)
    state = json.loads((repo / "state.fixture.json").read_text(encoding="utf-8"))
    state["resources"].append(
        {
            "mode": "managed",
            "type": "aws_s3_bucket_public_access_block",
            "name": "assets",
            "instances": [
                {
                    "attributes": {
                        "id": "acme-assets",
                        "bucket": "acme-assets",
                        **dict.fromkeys(FLAG_NAMES, True),
                    }
                }
            ],
        }
    )
    applied = tmp_path / "applied.json"
    applied.write_text(json.dumps(state), encoding="utf-8")
    vctx = VerifyContext(github=gh, clock=_clock, state_path=applied)
    outcome = run_verify("acme/infra#412", repo, config, vctx)
    assert outcome.result == "CONFIRMED", outcome.stages
    watch = next(s for s in outcome.stages if s.name == "watch")
    assert watch.status is StageStatus.SKIPPED and "scanners" in watch.summary


# --- pure helpers


def test_parse_log_line() -> None:
    line = (
        "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be acme-assets "
        "[06/Feb/2026:00:00:38 +0000] 192.0.2.3 - 3E57427F3EXAMPLE REST.GET.OBJECT img/a.png "
        '"GET /img/a.png HTTP/1.1" 200 - 113 113 7 6 "-" "curl/8.0" - abc= SigV4 '
        "ECDHE-RSA-AES128-GCM-SHA256 AuthHeader acme-assets.s3.amazonaws.com TLSv1.2 - -"
    )
    row = parse_log_line(line)
    assert row is not None
    assert (row.bucket, row.requester, row.operation, row.status) == (
        "acme-assets",
        "-",
        "REST.GET.OBJECT",
        200,
    )
    assert row.day == date(2026, 2, 6)
    assert parse_log_line("garbage") is None


@pytest.mark.parametrize(
    ("requester", "kind"),
    [
        ("-", "anonymous"),
        ("arn:aws:sts::123456789012:assumed-role/app/x", "in_account"),
        ("arn:aws:iam::210987654321:role/partner", "cross_account"),
        ("svc:logging.s3.amazonaws.com", "service"),
        ("79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be", "unknown"),
    ],
)
def test_classify(requester: str, kind: str) -> None:
    assert classify(requester, "123456789012") == kind


def test_plan_scope_create_rejects_an_update() -> None:
    plan = {
        "resource_changes": [
            {"address": "a.b", "change": {"actions": ["update"]}},
        ]
    }
    check = check_scope(plan, "a.b", expect="create")
    assert check.result.value == "fail" and "not created" in check.detail


class _Error(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}


class _FakeS3:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def _rec(self, name: str) -> None:
        self.calls.append(iam_action("s3", name))

    def get_bucket_policy_status(self, **kw: Any) -> Any:
        self._rec("get_bucket_policy_status")
        return {"PolicyStatus": {"IsPublic": True}}

    def get_bucket_acl(self, **kw: Any) -> Any:
        self._rec("get_bucket_acl")
        return {"Grants": []}

    def get_bucket_ownership_controls(self, **kw: Any) -> Any:
        self._rec("get_bucket_ownership_controls")
        return {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}

    def get_bucket_website(self, **kw: Any) -> Any:
        self._rec("get_bucket_website")
        raise _Error("NoSuchWebsiteConfiguration")

    def get_bucket_logging(self, **kw: Any) -> Any:
        self._rec("get_bucket_logging")
        return {"LoggingEnabled": {"TargetBucket": "acme-logs", "TargetPrefix": "s3/"}}

    def list_objects_v2(self, **kw: Any) -> Any:
        self._rec("list_objects_v2")
        return {
            "Contents": [
                {"Key": "s3/2026-10-01-00-00-00-ABCDEF0123456789"},
                {"Key": "s3/2026-11-01-00-00-00-ABCDEF0123456789"},
            ],
            "IsTruncated": False,
        }

    def get_object(self, **kw: Any) -> Any:
        self._rec("get_object")
        line = (
            "owner acme-assets [01/Oct/2026:00:00:38 +0000] 192.0.2.3 - REQ REST.GET.OBJECT k "
            '"GET /k HTTP/1.1" 200 - 1 1 1 1 "-" "ua" -'
        )

        class Body:
            def read(self) -> bytes:
                return line.encode()

        return {"Body": Body()}

    def list_buckets(self, **kw: Any) -> Any:
        self._rec("list_buckets")
        return {"Buckets": [{"Name": "acme-assets"}]}


class _FakeCloudFront:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def list_distributions(self, **kw: Any) -> Any:
        self.calls.append(iam_action("cloudfront", "list_distributions"))
        return {"DistributionList": {"Items": [], "IsTruncated": False}}


def test_live_source_reads_logs_with_allowlisted_calls_only() -> None:
    calls: list[str] = []
    s3 = ReadOnlyClient(_FakeS3(calls), "s3")
    cf = ReadOnlyClient(_FakeCloudFront(calls), "cloudfront")
    src = LiveS3Source(s3, cf, "123456789012")
    facts = src.bucket("acme-assets", date(2026, 8, 1), date(2026, 10, 30))
    assert facts.buckets[0].exposure.policy_public
    assert [r.requester for r in facts.buckets[0].rows] == ["-"]
    src.account(date(2026, 8, 1), date(2026, 10, 30))
    assert "s3:ListAllMyBuckets" in calls and "s3:ListBucket" in calls
    assert all(is_allowed(c) for c in calls), calls


Clock = Callable[[], datetime]
