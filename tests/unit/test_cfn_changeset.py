"""Opt-in change-set preview (FR-10a, NFR-2 exception): off by default, never executes."""

from __future__ import annotations

import re
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_cfn import _fake_aws
from test_readonly import Recorder

from posturanet.aws.changeset import (
    CHANGESET_ACTIONS,
    DENIED_ACTIONS,
    ChangeSetClient,
    changeset_policy,
)
from posturanet.aws.readonly import ALLOWLIST, MutatingCallBlocked, is_allowed
from posturanet.errors import UsageError
from posturanet.evidence import FileSource
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix_full

FIX = Path(__file__).resolve().parents[1] / "fixtures"
SRC = Path(__file__).resolve().parents[2] / "src" / "posturanet"
SG = FIX / "findings" / "sg_ssh_open.json"
FLOWS = FIX / "flows" / "bastion_90d.json"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
ROLE = "arn:aws:iam::123456789012:role/PosturaNetChangeSetPreview"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    dst = tmp_path / "repo"
    shutil.copytree(FIX / "cfn" / "basic", dst)
    return dst


class FakeCfn(Recorder):
    """A raw CloudFormation client: records every action, answers like AWS would."""

    def __init__(self, calls: list[str], body: str, change: dict[str, Any] | None = None) -> None:
        super().__init__("cloudformation", calls)
        self.body = body
        self.change = change or {
            "Type": "Resource",
            "ResourceChange": {
                "Action": "Modify",
                "LogicalResourceId": "BastionSG",
                "Replacement": "False",
            },
        }
        self.leftovers: list[dict[str, Any]] = []
        self.fail_delete = False

    def __getattr__(self, name: str) -> Any:
        record = super().__getattr__(name)

        def op(**kw: Any) -> Any:
            record(**kw)
            if name == "get_template":
                return {"TemplateBody": self.body}
            if name == "describe_stacks":
                return {
                    "Stacks": [
                        {
                            "StackStatus": "UPDATE_COMPLETE",
                            "Parameters": [{"ParameterKey": "Env"}],
                            "Capabilities": [],
                        }
                    ]
                }
            if name == "list_change_sets":
                return {"Summaries": self.leftovers}
            if name == "create_change_set":
                assert kw["ChangeSetType"] == "UPDATE"
                assert "RoleARN" not in kw
                return {"Id": "cs"}
            if name == "describe_change_set":
                return {"Status": "CREATE_COMPLETE", "Changes": [self.change]}
            if name == "delete_change_set" and self.fail_delete:
                raise RuntimeError("throttled")
            return {}

        return op


def _run(
    repo: Path,
    *,
    enabled: bool,
    change: dict[str, Any] | None = None,
    fail_delete: bool = False,
    leftovers: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any, list[str]]:
    config, _ = load_config(repo)
    config.evidence.min_confidence_for_pr = "medium"
    if enabled:
        config.cloudformation.changeset_preview.enabled = True
        config.cloudformation.changeset_preview.role_arn = ROLE
    body = (repo / "templates/network.yaml").read_text("utf-8")
    cs_calls: list[str] = []
    raw = FakeCfn(cs_calls, body, change)
    raw.fail_delete = fail_delete
    raw.leftovers = leftovers or []
    ctx = Context(
        mode="check",
        evidence=FileSource(FLOWS),
        clock=lambda: NOW,
        aws=_fake_aws(body),  # ReadOnlyClient: anything off the allowlist raises
        changeset=ChangeSetClient(lambda: raw, clock=lambda: NOW, sleep=lambda s: None),
    )
    record, proposal = run_fix_full(str(SG), repo, config, ctx)
    return record, proposal, cs_calls


def _check(proposal: Any) -> Any:
    return next(c for c in proposal.report.checks if c.id == "changeset")


def test_default_path_makes_no_changeset_calls(repo: Path) -> None:
    """Off by default: even with a client wired in, nothing outside the read-only list runs."""
    record, proposal, cs_calls = _run(repo, enabled=False)
    assert record.result == "VALIDATED", record.stages
    assert cs_calls == []
    check = _check(proposal)
    assert check.result.value == "skipped" and check.required is False


def test_opt_in_previews_and_always_deletes(repo: Path) -> None:
    record, proposal, cs_calls = _run(repo, enabled=True)
    assert record.result == "VALIDATED", record.stages
    assert cs_calls == [
        "cloudformation:DescribeStacks",
        "cloudformation:ListChangeSets",
        "cloudformation:CreateChangeSet",
        "cloudformation:DescribeChangeSet",
        "cloudformation:DeleteChangeSet",
    ]
    check = _check(proposal)
    assert check.result.value == "pass" and check.required is True
    assert "BastionSG" in check.detail


def test_opt_in_dry_run_creates_nothing(repo: Path) -> None:
    config, _ = load_config(repo)
    config.cloudformation.changeset_preview.enabled = True
    config.cloudformation.changeset_preview.role_arn = ROLE
    calls: list[str] = []
    ctx = Context(
        evidence=FileSource(FLOWS),
        clock=lambda: NOW,
        changeset=ChangeSetClient(lambda: FakeCfn(calls, ""), sleep=lambda s: None),
    )
    _, proposal = run_fix_full(str(SG), repo, config, ctx)
    assert calls == []
    assert _check(proposal).result.value == "skipped"


@pytest.mark.parametrize(
    ("replacement", "action", "logical"),
    [("True", "Modify", "BastionSG"), ("Conditional", "Modify", "BastionSG"),
     ("False", "Remove", "BastionSG"), ("False", "Modify", "WebSG")],
)  # fmt: skip
def test_replacement_or_wider_change_stops(
    repo: Path, replacement: str, action: str, logical: str
) -> None:
    change = {
        "Type": "Resource",
        "ResourceChange": {
            "Action": action,
            "LogicalResourceId": logical,
            "Replacement": replacement,
        },
    }
    record, proposal, cs_calls = _run(repo, enabled=True, change=change)
    assert record.result == "STOPPED"
    assert cs_calls[-1] == "cloudformation:DeleteChangeSet"


def test_failed_delete_fails_closed(repo: Path) -> None:
    record, _, cs_calls = _run(repo, enabled=True, fail_delete=True)
    assert record.result == "STOPPED"
    assert any("NOT deleted" in s.summary or "NOT deleted" in str(s) for s in record.stages)


def test_sweep_deletes_only_old_posturanet_change_sets(repo: Path) -> None:
    old = NOW - timedelta(hours=2)
    leftovers = [
        {"ChangeSetName": "posturanet-aaaaaaaaaaaa", "CreationTime": old},
        {"ChangeSetName": "posturanet-bbbbbbbbbbbb", "CreationTime": NOW},
        {"ChangeSetName": "team-release", "CreationTime": old},
    ]
    _, _, cs_calls = _run(repo, enabled=True, leftovers=leftovers)
    assert cs_calls.count("cloudformation:DeleteChangeSet") == 2  # the old one + our own


def test_client_cannot_execute() -> None:
    client = ChangeSetClient(lambda: FakeCfn([], ""))
    assert not hasattr(client, "execute")
    assert not hasattr(client, "execute_change_set")
    with pytest.raises(MutatingCallBlocked):
        client._call("execute_change_set", StackName="s", ChangeSetName="posturanet-x")
    with pytest.raises(ValueError):
        client.delete("s", "team-release")


def test_execute_never_appears_in_source() -> None:
    """The only mention of ExecuteChangeSet in src/ is the Deny in the preview policy."""
    hits = []
    for py in SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        if "execute_change_set" in text:
            hits.append(f"{py.name}: execute_change_set")
        if re.search(r"ExecuteChangeSet", text) and py.name != "changeset.py":
            hits.append(f"{py.name}: ExecuteChangeSet")
    assert hits == []


def test_policies_stay_apart() -> None:
    assert not set(CHANGESET_ACTIONS) & set(ALLOWLIST)
    assert not any(is_allowed(a) for a in CHANGESET_ACTIONS if "Change" in a)
    policy = changeset_policy()
    allowed = {a for s in policy["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
    denied = {a for s in policy["Statement"] if s["Effect"] == "Deny" for a in s["Action"]}
    assert allowed == set(CHANGESET_ACTIONS)
    assert "cloudformation:ExecuteChangeSet" in denied and denied == set(DENIED_ACTIONS)
    assert not allowed & denied


def test_config_needs_its_own_role(tmp_path: Path) -> None:
    (tmp_path / ".posturanet.yml").write_text(
        "cloudformation:\n  changeset_preview:\n    enabled: true\n", "utf-8"
    )
    with pytest.raises(UsageError, match="own role_arn"):
        load_config(tmp_path)
    (tmp_path / ".posturanet.yml").write_text(
        f"aws:\n  role_arn: {ROLE}\n"
        f"cloudformation:\n  changeset_preview:\n    enabled: true\n    role_arn: {ROLE}\n",
        "utf-8",
    )
    with pytest.raises(UsageError, match="must differ"):
        load_config(tmp_path)
    assert load_config(tmp_path.parent)[0].cloudformation.changeset_preview.enabled is False


# --- groups with standalone SecurityGroupIngress resources

SPLIT = """Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: bastion
  SshIn:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: {GroupId: !Ref Sg, IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0}
  MetricsIn:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: {GroupId: !GetAtt Sg.GroupId, IpProtocol: tcp, FromPort: 9100, ToPort: 9100,
                 CidrIp: 10.0.0.0/16}
  OtherSg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: other
"""


def _rc(logical: str, action: str = "Modify", replacement: str = "False") -> dict[str, Any]:
    return {
        "Type": "Resource",
        "ResourceChange": {
            "Action": action,
            "LogicalResourceId": logical,
            "Replacement": replacement,
        },
    }


def _split(tmp_path: Path) -> Any:
    from posturanet import cfn
    from posturanet.models.config import Config

    (tmp_path / "t.yaml").write_text(SPLIT, "utf-8")
    res = cfn.resolve(tmp_path, Config(), "s", "Sg")
    assert isinstance(res, cfn.CfnResource)
    return res


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        # CloudFormation replaces an ingress resource to change its CIDR.
        ([_rc("SshIn", replacement="True")], "only 1 of Sg's ingress resource(s)"),
        ([_rc("Sg"), _rc("SshIn", "Remove")], "plus 1 of its own ingress resource(s)"),
        ([_rc("SshIn", "Remove"), _rc("SshNew", "Add")], "only 2 of Sg's"),
    ],
)
def test_own_ingress_resources_may_change(
    tmp_path: Path, changes: list[dict[str, Any]], detail: str
) -> None:
    from posturanet.cfn.validate import _judge, _own_ingress
    from posturanet.models import CheckResult

    res = _split(tmp_path)
    # The edit replaced SshIn's rule with a new resource SshNew.
    edited = SPLIT.replace(
        "  MetricsIn:",
        "  SshNew:\n    Type: AWS::EC2::SecurityGroupIngress\n"
        "    Properties: {GroupId: !Ref Sg, IpProtocol: tcp, FromPort: 22, ToPort: 22,"
        " CidrIp: 192.0.2.10/32}\n  MetricsIn:",
    )
    own = _own_ingress(res, edited)
    assert own == {"SshIn", "MetricsIn", "SshNew"}
    result, text = _judge(res, {"Status": "CREATE_COMPLETE", "Changes": changes}, own)
    assert result is CheckResult.PASS, text
    assert detail in text


@pytest.mark.parametrize(
    "changes",
    [
        [_rc("Sg"), _rc("OtherSg")],  # another group
        [_rc("SshIn"), _rc("Unrelated", "Add")],  # a resource that isn't Sg's
        [_rc("Sg", replacement="True"), _rc("SshIn")],  # the group itself replaced
        [_rc("SshIn", "Dynamic")],  # an action that isn't add, modify or remove
        [],
    ],
)
def test_other_changes_still_stop(tmp_path: Path, changes: list[dict[str, Any]]) -> None:
    from posturanet.cfn.validate import _judge, _own_ingress
    from posturanet.models import CheckResult

    res = _split(tmp_path)
    own = _own_ingress(res, SPLIT)
    result, _ = _judge(res, {"Status": "CREATE_COMPLETE", "Changes": changes}, own)
    assert result is CheckResult.FAIL
