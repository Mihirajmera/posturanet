"""IAM least privilege (FR-51): evidence, shrink, edits in 3 policy forms, validation, verify."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fakes import FakeGitHub, IamTerraform
from posturanet.aws.readonly import ReadOnlyClient, iam_action, is_allowed
from posturanet.deliver import GitHub
from posturanet.deliver.idempotency import spec_in
from posturanet.evidence import FileSource
from posturanet.iamfix import contract as iamcontract
from posturanet.iamfix.doc import Statement, realign, statements_from_json
from posturanet.iamfix.evidence import LiveIamSource
from posturanet.iamfix.shrink import ServiceUse, check_invariants, recheck, shrink
from posturanet.models import StageStatus
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix
from posturanet.verify import VerifyContext, run_verify
from posturanet.verify.iam_signals import CloudTrailDenied, Denied, regressions
from posturanet.verify.signals import RejectFile

FIXTURES = Path(__file__).parent.parent / "fixtures"
APP = str(FIXTURES / "findings" / "iam21_app.json")
ADMIN = str(FIXTURES / "findings" / "iam1_admin.json")
DEPLOY = str(FIXTURES / "findings" / "iam21_deploy.json")


def _clock() -> datetime:
    return datetime(2026, 10, 30, 6, tzinfo=UTC)


def _ev(name: str) -> FileSource:
    return FileSource(FIXTURES / "iam" / name)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    out = tmp_path / "repo"
    shutil.copytree(FIXTURES / "tf" / "iam", out)
    return out


def _status(record: Any) -> dict[str, StageStatus]:
    return {s.name: s.status for s in record.stages}


# --- end to end, three policy forms


def test_jsonencode_service_wildcard_is_replaced(repo: Path) -> None:
    config, _ = load_config(repo)
    tf = IamTerraform("app")
    record = run_fix(
        APP,
        repo,
        config,
        Context(mode="check", evidence=_ev("app.json"), terraform=tf, clock=_clock),
    )
    assert record.result == "VALIDATED", record.stages
    assert record.diff is not None
    new = record.diff.files[0].new_content
    assert '"ec2:DescribeInstances", "ec2:DescribeVolumes", "logs:CreateLogStream"' in new
    assert '"ec2:*"' not in new
    assert 'Action   = "ec2:TerminateInstances"' in new, "Deny statement untouched"
    assert record.validation is not None
    assert {c.id: c.result.value for c in record.validation.checks if c.required} == {
        "guardrails": "pass",
        "recheck": "pass",
        "invariants": "pass",
        "fmt": "pass",
        "validate": "pass",
        "plan_scope": "pass",
        "plan_matches": "pass",
    }
    assert (repo / "posturanet/contracts/aws_iam_policy.app.yaml").is_file()


def test_heredoc_admin_star_is_replaced(repo: Path) -> None:
    config, _ = load_config(repo)
    ctx = Context(mode="dry-run", evidence=_ev("admin.json"), clock=_clock)
    stopped = run_fix(ADMIN, repo, config, ctx)
    assert stopped.result == "STOPPED" and stopped.exit_code == 3
    assert "iam:PassRole isn't in last-accessed data" in " ".join(stopped.stages[2].details)

    # A human confirms the full IAM action list: PassRole is dropped on purpose.
    path = repo / "posturanet/contracts/aws_iam_policy.admin.yaml"
    assert not path.exists(), "dry run writes nothing"
    run_fix(ADMIN, repo, config, Context(mode="check", evidence=_ev("admin.json"), clock=_clock))
    draft = iamcontract.load(path)
    assert draft is not None and any("PassRole" in r for r in draft.needs_review)
    iamcontract.write(
        path, draft.model_copy(update={"status": "approved", "reviewed_services": ["iam"]})
    )
    record = run_fix(ADMIN, repo, config, ctx)
    assert record.result == "DRY RUN", record.stages
    assert record.diff is not None
    new = record.diff.files[0].new_content
    block = new[new.index("<<EOF") : new.index("\nEOF")]
    doc = json.loads(block.split("\n", 1)[1])
    assert doc["Statement"][0]["Action"] == [
        "ec2:DescribeInstances",
        "iam:GetRole",
        "iam:ListRoles",
    ]
    assert "rds" not in block, "unused services are dropped"


def test_policy_document_data_plane_service_needs_review(repo: Path) -> None:
    config, _ = load_config(repo)
    ctx = Context(
        mode="check", evidence=_ev("deploy.json"), terraform=IamTerraform("deploy"), clock=_clock
    )
    stopped = run_fix(DEPLOY, repo, config, ctx)
    assert stopped.result == "STOPPED" and stopped.exit_code == 3
    assert "s3 data actions" in stopped.stages[2].details[0]
    path = repo / "posturanet/contracts/aws_iam_policy.deploy.yaml"
    draft = iamcontract.load(path)
    assert draft is not None and draft.needs_review

    approved = draft.model_copy(
        update={
            "status": "approved",
            "reviewed_services": ["s3"],
            "must_allow": [
                *draft.must_allow,
                iamcontract.IamAllowed(action="s3:GetObject", source="human", owner="@ci"),
            ],
        }
    )
    iamcontract.write(path, approved)
    record = run_fix(DEPLOY, repo, config, ctx)
    assert record.result == "VALIDATED", record.stages
    assert record.diff is not None
    new = record.diff.files[0].new_content
    listed = [ln.strip().strip(",") for ln in new.splitlines() if ln.strip().startswith('"')]
    assert listed[-4:] == [
        '"iam:PassRole"',
        '"s3:GetObject"',
        '"s3:ListAllMyBuckets"',
        '"s3:PutBucketPolicy"',
    ], "4 actions render one per line"


def test_service_without_action_data_stops(repo: Path) -> None:
    config, _ = load_config(repo)
    record = run_fix(
        APP,
        repo,
        config,
        Context(mode="dry-run", evidence=_ev("app_unknown_service.json"), clock=_clock),
    )
    assert record.result == "STOPPED"
    assert "no action-level data" in (record.stages[2].summary + " ".join(record.stages[2].details))


def test_unattached_policy_stops_unknown(repo: Path) -> None:
    config, _ = load_config(repo)
    record = run_fix(
        APP,
        repo,
        config,
        Context(mode="dry-run", evidence=_ev("app_unattached.json"), clock=_clock),
    )
    assert record.result == "STOPPED" and record.exit_code == 3
    evidence = next(s for s in record.stages if s.name == "evidence")
    assert evidence.status is StageStatus.UNKNOWN
    assert "isn't attached" in evidence.summary


def test_plan_changing_other_attributes_fails(repo: Path) -> None:
    config, _ = load_config(repo)
    tf = IamTerraform("app", extra_attr=True)
    record = run_fix(
        APP,
        repo,
        config,
        Context(mode="check", evidence=_ev("app.json"), terraform=tf, clock=_clock),
    )
    assert record.result == "STOPPED" and record.exit_code == 4
    assert any("plan also changes name" in s.summary for s in record.stages)


def test_crlf_file_is_edited_and_kept_crlf(repo: Path) -> None:
    main = repo / "main.tf"
    main.write_bytes(main.read_bytes().replace(b"\n", b"\r\n"))
    config, _ = load_config(repo)
    record = run_fix(
        APP, repo, config, Context(mode="dry-run", evidence=_ev("app.json"), clock=_clock)
    )
    assert record.result == "DRY RUN", record.stages
    assert record.diff is not None
    new = record.diff.files[0].new_content
    assert "\r\n" in new and "\n" not in new.replace("\r\n", "")


def test_dry_run_without_evidence_stops_after_locate(repo: Path) -> None:
    config, _ = load_config(repo)
    record = run_fix(DEPLOY, repo, config, Context(mode="dry-run"))
    assert record.result == "DRY RUN"
    locate = next(s for s in record.stages if s.name == "locate")
    assert any("policy document: policy_document" in d for d in locate.details)


# --- deliver + verify


def _applied_state(repo: Path, tmp_path: Path, actions: list[str]) -> Path:
    state = json.loads((repo / "state.fixture.json").read_text(encoding="utf-8"))
    for res in state["resources"]:
        if res["name"] == "app":
            res["instances"][0]["attributes"]["policy"] = json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Sid": "Compute", "Effect": "Allow", "Action": actions, "Resource": "*"},
                        {"Effect": "Deny", "Action": "ec2:TerminateInstances", "Resource": "*"},
                    ],
                }
            )
    out = tmp_path / "applied.json"
    out.write_text(json.dumps(state), encoding="utf-8")
    return out


def _open(repo: Path) -> tuple[FakeGitHub, GitHub]:
    config, _ = load_config(repo)
    fake = FakeGitHub({"main.tf": (repo / "main.tf").read_text(encoding="utf-8")})
    gh = GitHub("t", "acme/infra", fake.client())
    ctx = Context(
        mode="open-pr",
        evidence=_ev("app.json"),
        terraform=IamTerraform("app"),
        github=gh,
        clock=_clock,
    )
    record = run_fix(APP, repo, config, ctx)
    assert record.result == "OPENED", record.stages
    return fake, gh


def test_open_pr_body_and_spec(repo: Path) -> None:
    fake, _ = _open(repo)
    pr = fake.prs[0]
    assert pr["title"] == "🔒 PosturaNet: replace wildcard actions in app (IAM.21)"
    assert "### Used actions kept" in pr["body"] and "`role/app`" in pr["body"]
    spec = spec_in(pr["body"])
    assert spec is not None and spec.fix_type == "iam_least_privilege"
    assert spec.actions_removed == ["ec2:*"] and spec.principals == ["role/app"]
    assert spec.watch_hours == 72
    assert pr["head"]["ref"].startswith("posturanet/iam/iam-21-app-")


def test_verify_watches_then_confirms(repo: Path, tmp_path: Path) -> None:
    fake, gh = _open(repo)
    config, _ = load_config(repo)
    fake.merge(412, merged_at="2026-10-30T12:00:00Z")
    state = _applied_state(
        repo, tmp_path, ["ec2:DescribeInstances", "ec2:DescribeVolumes", "logs:CreateLogStream"]
    )
    denied = tmp_path / "denied.json"
    denied.write_text(json.dumps({"denied": []}), encoding="utf-8")

    def at(h: int) -> datetime:
        return datetime(2026, 10, 30, 12, tzinfo=UTC) + timedelta(hours=h)

    early = VerifyContext(
        github=gh, clock=lambda: at(10), state_path=state, rejects=RejectFile(denied)
    )
    watching = run_verify("acme/infra#412", repo, config, early)
    assert watching.result == "WATCHING", watching.stages
    late = VerifyContext(
        github=gh, clock=lambda: at(80), state_path=state, rejects=RejectFile(denied)
    )
    done = run_verify("acme/infra#412", repo, config, late)
    assert done.result == "CONFIRMED", done.stages


def test_verify_regression_opens_revert(repo: Path, tmp_path: Path) -> None:
    fake, gh = _open(repo)
    config, _ = load_config(repo)
    fake.merge(412, merged_at="2026-10-30T12:00:00Z")
    state = _applied_state(
        repo, tmp_path, ["ec2:DescribeInstances", "ec2:DescribeVolumes", "logs:CreateLogStream"]
    )
    denied = tmp_path / "denied.json"
    denied.write_text(
        json.dumps(
            {
                "denied": [
                    {
                        "principal": "role/app",
                        "action": "ec2:StopInstances",
                        "hour": "2026-10-31T03:00:00Z",
                        "n": 4,
                    },
                    {
                        "principal": "role/other",
                        "action": "ec2:StopInstances",
                        "hour": "2026-10-31T03:00:00Z",
                    },
                    {
                        "principal": "role/app",
                        "action": "ec2:DescribeInstances",
                        "hour": "2026-10-31T03:00:00Z",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    ctx = VerifyContext(
        github=gh,
        clock=lambda: datetime(2026, 11, 1, tzinfo=UTC),
        state_path=state,
        rejects=RejectFile(denied),
        open_pr=True,
    )
    record = run_verify("acme/infra#412", repo, config, ctx)
    assert record.result == "REGRESSED", record.stages
    assert record.outcome is not None
    assert record.outcome.regressions == [
        "role/app → ec2:StopInstances · 4 denied (allowed before the fix)"
    ]
    assert record.pr_url and fake.prs[-1]["head"]["ref"].startswith("posturanet/revert/")


def test_verify_not_applied_while_wildcard_in_state(repo: Path, tmp_path: Path) -> None:
    fake, gh = _open(repo)
    config, _ = load_config(repo)
    fake.merge(412)
    state = _applied_state(repo, tmp_path, ["ec2:*", "logs:CreateLogStream"])
    record = run_verify("acme/infra#412", repo, config, VerifyContext(github=gh, state_path=state))
    assert record.result == "NOT APPLIED"


# --- pure


def _st(actions: list[str], effect: str = "Allow", **kw: Any) -> Statement:
    return Statement(
        index=0,
        sid=None,
        effect=effect,
        actions=actions,
        not_action=False,
        resources=["*"],
        span=(0, 1),
        indent="",
        **kw,
    )


def test_shrink_keeps_explicit_and_partial_wildcards() -> None:
    use = {"ec2": ServiceUse("ec2", True, True, {"ec2:DescribeInstances", "ec2:GetConsoleOutput"})}
    res = shrink("IAM.21", [_st(["ec2:*", "ec2:Get*", "sts:GetCallerIdentity"])], use)
    assert not res.blockers
    assert res.changes[0].after == ["ec2:DescribeInstances", "ec2:Get*", "sts:GetCallerIdentity"]


def test_shrink_iam1_only_touches_star() -> None:
    use = {"ec2": ServiceUse("ec2", True, True, {"ec2:DescribeInstances"})}
    res = shrink("IAM.1", [_st(["*", "s3:*"])], use, reviewed=frozenset({"iam"}))
    assert res.changes[0].after == ["ec2:DescribeInstances", "s3:*"]


def test_shrink_never_drops_untracked_passrole_silently() -> None:
    use = {"iam": ServiceUse("iam", True, True, {"iam:GetRole"})}
    blocked = shrink("IAM.21", [_st(["iam:*"])], use)
    assert any("iam:PassRole isn't in last-accessed data" in b for b in blocked.blockers)
    kept = shrink("IAM.21", [_st(["iam:*"])], use, extra=["iam:PassRole"])
    assert not kept.blockers and kept.changes[0].after == ["iam:GetRole", "iam:PassRole"]
    explicit = shrink("IAM.21", [_st(["iam:PassRole", "ec2:*"])], {})
    assert not any("PassRole" in b for b in explicit.blockers), "explicit PassRole is kept"
    reviewed = shrink("IAM.21", [_st(["iam:*"])], use, reviewed=frozenset({"iam"}))
    assert not reviewed.blockers and reviewed.changes[0].after == ["iam:GetRole"]


def test_shrink_not_action_blocks() -> None:
    st_ = Statement(0, "x", "Allow", None, True, ["*"], None, "")
    assert shrink("IAM.21", [st_], {}).blockers == [
        "statement x uses NotAction; PosturaNet doesn't shrink it"
    ]


def test_shrink_empty_statement_blocks() -> None:
    res = shrink("IAM.21", [_st(["rds:*"])], {"rds": ServiceUse("rds", False, True)})
    assert res.blockers == ["statement 1 allowed nothing that was used; remove it by hand"]


@given(
    used=st.sets(st.sampled_from(["DescribeInstances", "RunInstances", "StopInstances", "GetX"])),
    keep=st.lists(st.sampled_from(["ec2:Get*", "sts:GetCallerIdentity", "logs:PutLogEvents"])),
)
def test_shrink_invariants_hold(used: set[str], keep: list[str]) -> None:
    use = {"ec2": ServiceUse("ec2", True, True, {f"ec2:{a}" for a in used})}
    res = shrink("IAM.21", [_st(["ec2:*", *keep])], use)
    if res.changes:
        assert check_invariants(res.changes, use, []) == []
        ok, _ = recheck("IAM.21", [{"Effect": "Allow", "Action": res.changes[0].after}])
        assert ok


def test_recheck_rules() -> None:
    assert not recheck("IAM.1", [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}])[0]
    assert recheck("IAM.1", [{"Effect": "Allow", "Action": ["*"], "Resource": ["arn:x"]}])[0]
    assert not recheck("IAM.21", [{"Effect": "Allow", "Action": ["S3:*"]}])[0]
    assert recheck("IAM.21", [{"Effect": "Deny", "Action": ["s3:*"]}])[0]
    assert statements_from_json('{"Statement": {"Effect": "Allow", "Action": "a:b"}}') == [
        {"Effect": "Allow", "Action": ["a:b"]}
    ]


def test_realign_matches_terraform_fmt_rules() -> None:
    text = 'x {\n  a = 1\n  bbb = [\n    "q",\n  ]\n  cc = 2\n  d = 3\n}\n'
    out = realign(text, 0, len(text), "  ")
    assert out == 'x {\n  a = 1\n  bbb = [\n    "q",\n  ]\n  cc = 2\n  d  = 3\n}\n'


def test_regressions_only_for_removed_and_not_kept() -> None:
    t = datetime(2026, 10, 31, tzinfo=UTC)
    rows = [
        Denied("role/a", "ec2:RunInstances", t, 2),
        Denied("role/a", "ec2:DescribeInstances", t),
    ]
    assert regressions(rows, ["ec2:*"], ["ec2:DescribeInstances"]) == [
        "role/a → ec2:RunInstances · 2 denied (allowed before the fix)"
    ]


# --- live sources, allowlisted calls only


class _FakeIam:
    def __init__(self, calls: list[str]) -> None:
        self.calls, self.polls = calls, 0

    def _rec(self, name: str) -> None:
        self.calls.append(iam_action("iam", name))

    def get_policy(self, **kw: Any) -> Any:
        self._rec("get_policy")
        return {"Policy": {"CreateDate": datetime(2025, 1, 1, tzinfo=UTC)}}

    def list_entities_for_policy(self, **kw: Any) -> Any:
        self._rec("list_entities_for_policy")
        return {"PolicyRoles": [{"RoleName": "app"}], "IsTruncated": False}

    def generate_service_last_accessed_details(self, **kw: Any) -> Any:
        self._rec("generate_service_last_accessed_details")
        assert kw["Granularity"] == "ACTION_LEVEL"
        return {"JobId": "j"}

    def get_service_last_accessed_details(self, **kw: Any) -> Any:
        self._rec("get_service_last_accessed_details")
        self.polls += 1
        if self.polls == 1:
            return {"JobStatus": "IN_PROGRESS"}
        return {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceNamespace": "ec2",
                    "LastAuthenticated": datetime(2026, 10, 1, tzinfo=UTC),
                    "TrackedActionsLastAccessed": [
                        {
                            "ActionName": "DescribeInstances",
                            "LastAccessedTime": datetime(2026, 10, 1, tzinfo=UTC),
                        },
                        {"ActionName": "RunInstances"},
                    ],
                },
                {"ServiceNamespace": "ssm", "LastAuthenticated": datetime(2026, 9, 1, tzinfo=UTC)},
            ],
            "IsTruncated": False,
        }


class _FakeCloudTrail:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def lookup_events(self, **kw: Any) -> Any:
        self.calls.append(iam_action("cloudtrail", "lookup_events"))
        event = {
            "errorCode": "AccessDenied",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "RunInstances",
            "eventTime": "2026-10-31T01:02:03Z",
            "userIdentity": {
                "sessionContext": {"sessionIssuer": {"arn": "arn:aws:iam::123456789012:role/app"}}
            },
        }
        return {"Events": [{"CloudTrailEvent": json.dumps(event)}]}


def test_live_sources_make_allowlisted_calls_only() -> None:
    calls: list[str] = []
    iam = ReadOnlyClient(_FakeIam(calls), "iam")
    ev = LiveIamSource(iam, sleep=lambda s: None).policy(
        "arn:aws:iam::123456789012:policy/app", datetime(2026, 10, 30).date()
    )
    assert ev.principals == ["role/app"]
    ec2 = next(s for s in ev.services if s.namespace == "ec2")
    assert [a.action for a in ec2.actions if a.last_seen] == ["ec2:DescribeInstances"]
    assert next(s for s in ev.services if s.namespace == "ssm").action_level is False

    ct = ReadOnlyClient(_FakeCloudTrail(calls), "cloudtrail")
    rows = CloudTrailDenied(ct).denied(
        ["role/app"], ["ec2"], datetime(2026, 10, 30, tzinfo=UTC), datetime(2026, 11, 2, tzinfo=UTC)
    )
    assert [(r.principal, r.action) for r in rows] == [("role/app", "ec2:RunInstances")]
    assert "cloudtrail:LookupEvents" in calls
    assert all(is_allowed(c) for c in calls), calls
