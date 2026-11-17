"""CloudFormation parameters, conditions and nested stacks (FR-10a)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from test_readonly import Recorder

from posturanet import cfn
from posturanet.aws.readonly import ReadOnlyClient, is_allowed
from posturanet.cfn.edit import iam_edit, render_sg
from posturanet.cfn.params import Scope, Unresolved
from posturanet.cfn.template import parse
from posturanet.errors import StageStop
from posturanet.ingest import ingest
from posturanet.models.config import load_config
from posturanet.synth.sg_rules import Rule
from posturanet.synth.sg_z3 import Synthesis

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "cfn"
APP_SG, ADMIN_SG, DEBUG_SG = "sg-0c33d5e7", "sg-0d44e6f8", "sg-0e55f7a9"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    dst = tmp_path / "repo"
    shutil.copytree(FIX / "nested", dst)
    return dst


def _locate(repo: Path, sg: str, aws: Any = None) -> cfn.CfnResource:
    config, _ = load_config(repo)
    if aws is not None:
        config.cloudformation.stack_resources = None
    _, res = cfn.locate(ingest(sg), repo, config, None, aws, [cfn.SG_TYPE])
    return res


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text("utf-8")
    assert old in text
    path.write_bytes(text.replace(old, new).encode("utf-8"))


def _scope(text: str, tmp_path: Path) -> Scope:
    t = parse("Resources:\n  X:\n    Type: AWS::SNS::Topic\n" + text, tmp_path / "t.yaml")
    return Scope(t, "s")


# --- nested stacks


def test_nested_stack_follows_template_url(repo: Path) -> None:
    config, _ = load_config(repo)
    loc, res = cfn.locate(ingest(APP_SG), repo, config, None, None, [cfn.SG_TYPE])
    assert (loc.file, res.stack) == ("templates/nested/network.yaml", "app-NetworkStack-EXAMPLE")
    assert "parameter values from template defaults" in loc.reasoning
    # The parent's values win over the nested defaults; NoEcho is never read.
    params = res.scope.params()
    assert params["Env"] == "prod" and params["MonitoringCidr"] == "10.0.0.0/16"
    assert "DbPassword" not in params


def test_nested_stack_remote_template_url_is_unknown(repo: Path) -> None:
    _edit(
        repo / "templates/app.yaml",
        "TemplateURL: nested/network.yaml",
        "TemplateURL: https://example.com/network.yaml",
    )
    with pytest.raises(StageStop) as exc:
        _locate(repo, APP_SG)
    assert exc.value.unknown and "is a URL" in exc.value.reason


def test_nested_stack_outside_repo_is_unknown(repo: Path) -> None:
    _edit(repo / "templates/app.yaml", "nested/network.yaml", "../../../network.yaml")
    with pytest.raises(StageStop) as exc:
        _locate(repo, APP_SG)
    assert exc.value.unknown and "outside the repo" in exc.value.reason


def test_nested_stack_live_uses_describe_stacks(repo: Path) -> None:
    calls: list[str] = []
    rows = json.loads((repo / "stack-resources.json").read_text("utf-8"))

    class Cfn(Recorder):
        def __getattr__(self, name: str) -> Any:
            op = super().__getattr__(name)

            def wrapped(**kw: Any) -> Any:
                op(**kw)
                if name == "describe_stacks":
                    assert kw == {"StackName": "app-NetworkStack-EXAMPLE"}
                    params = [
                        {"ParameterKey": "Env", "ParameterValue": "dev"},
                        {"ParameterKey": "MonitoringCidr", "ParameterValue": "198.51.100.0/24"},
                        {"ParameterKey": "DbPassword", "ParameterValue": "****"},
                    ]
                    return {"Stacks": [{"Parameters": params}]}
                return rows

            return wrapped

    res = _locate(repo, APP_SG, lambda s: ReadOnlyClient(Cfn(s, calls), s))
    assert sorted(cfn.parse_sg(res).rules()) == sorted(
        [Rule("0.0.0.0/0", 22, 22, "tcp"), Rule("198.51.100.0/24", 9100, 9100, "tcp")]
    )  # Env=dev, so the IsProd entry is absent
    # The finding's stack, then each stack id up the chain, then the nested stack's parameters.
    assert calls == ["cloudformation:DescribeStackResources"] * 3 + [
        "cloudformation:DescribeStacks"
    ]
    assert all(is_allowed(c) for c in calls)


# --- parameters


def test_parameter_rules_resolve_and_parameterised_entries_stay(repo: Path) -> None:
    res = _locate(repo, APP_SG)
    sg = cfn.parse_sg(res)
    assert sg.rules() == sorted(
        [
            Rule("0.0.0.0/0", 22, 22, "tcp"),
            Rule("10.0.0.0/16", 9100, 9100, "tcp"),
            Rule("10.1.0.0/16", 443, 443, "tcp"),
        ]
    )
    synth = Synthesis(sg.rules(), [], [Rule("203.0.113.7/32", 22, 22, "tcp")], [], [], [])
    new = render_sg(sg, synth)
    assert "CidrIp: 203.0.113.7/32" in new and "CidrIp: 0.0.0.0/0" not in new
    assert "CidrIp: !Ref MonitoringCidr" in new and "- !If\n          - IsProd" in new
    t = parse(new, res.template.path)
    edited = cfn.CfnResource(res.stack, "AppSG", cfn.SG_TYPE, t, t.resources["AppSG"], 1, res.scope)
    assert Rule("10.0.0.0/16", 9100, 9100, "tcp") in cfn.parse_sg(edited).rules()


def test_open_rule_from_a_parameter_stops_unknown(repo: Path) -> None:
    sg = cfn.parse_sg(_locate(repo, ADMIN_SG))
    assert sg.rules() == [Rule("0.0.0.0/0", 22, 22, "tcp")]
    with pytest.raises(StageStop) as exc:
        render_sg(sg, Synthesis(sg.rules(), [], [], [], [], []))
    assert exc.value.unknown
    assert "parameter AdminCidr" in exc.value.reason and "parameter SshPort" in exc.value.reason


def test_unknown_parameter_value_stops_unknown(repo: Path) -> None:
    _edit(repo / "templates/app.yaml", "Env: !Ref Env", "Env: !Ref AWS::Region")
    with pytest.raises(StageStop) as exc:
        cfn.parse_sg(_locate(repo, APP_SG))
    assert exc.value.unknown and "condition IsProd" in exc.value.reason


def test_noecho_value_never_surfaces(tmp_path: Path) -> None:
    scope = _scope(
        "Parameters:\n  Pw:\n    Type: String\n    NoEcho: true\n    Default: hunter2\n",
        tmp_path,
    )
    with pytest.raises(Unresolved) as exc:
        scope.resolve({"Ref": "Pw"})
    assert "NoEcho" in str(exc.value) and "hunter2" not in str(exc.value)
    assert scope.params() == {}


def test_s3_flag_from_parameter(tmp_path: Path) -> None:
    text = (
        "Parameters:\n  Block:\n    Type: String\n    Default: '{v}'\n"
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      PublicAccessBlockConfiguration:\n        BlockPublicAcls: !Ref Block\n"
    )
    for v, stops in (("true", False), ("false", True)):
        t = parse(text.replace("{v}", v), tmp_path / "s.yaml")
        res = cfn.CfnResource("s", "B", cfn.BUCKET_TYPE, t, t.resources["B"], 6, Scope(t, "s"))
        assert cfn.s3_flags(res)["block_public_acls"] == v
        if stops:
            with pytest.raises(StageStop) as exc:
                cfn.s3_diff(tmp_path, res)
            assert exc.value.unknown and "parameter Block" in exc.value.reason
        else:
            _, already = cfn.s3_diff(tmp_path, res)
            assert already == ["BlockPublicAcls"]


def test_iam_action_from_parameter_stops_on_change(tmp_path: Path) -> None:
    text = (
        "Parameters:\n  Acts:\n    Type: CommaDelimitedList\n    Default: 's3:*,sqs:SendMessage'\n"
        "Resources:\n  P:\n    Type: AWS::IAM::ManagedPolicy\n    Properties:\n"
        "      PolicyDocument:\n        Statement:\n          - Effect: Allow\n"
        "            Action: !Ref Acts\n            Resource: '*'\n"
    )
    t = parse(text, tmp_path / "p.yaml")
    res = cfn.CfnResource("s", "P", cfn.POLICY_TYPE, t, t.resources["P"], 6, Scope(t, "s"))
    policy = cfn.parse_policy(res)
    assert policy.statements[0].actions == ["s3:*", "sqs:SendMessage"]
    with pytest.raises(StageStop) as exc:
        iam_edit(policy, {0: ["s3:GetObject"]})
    assert exc.value.unknown and "parameter Acts" in exc.value.reason


# --- conditions


def test_resource_condition_false_is_unknown(repo: Path) -> None:
    with pytest.raises(StageStop) as exc:
        _locate(repo, DEBUG_SG)
    assert exc.value.unknown and "Condition IsDev" in exc.value.reason


def test_conditions_evaluate_only_when_known(tmp_path: Path) -> None:
    scope = _scope(
        "Parameters:\n  E:\n    Type: String\n    Default: prod\n"
        "Conditions:\n  P: !Equals [!Ref E, prod]\n  R: !Equals [!Ref AWS::Region, us-east-1]\n"
        "  A: !And [!Condition P, !Condition R]\n  O: !Or [!Condition P, !Condition R]\n"
        "  N: !Not [!Condition R]\n  Loop: !Not [!Condition Loop]\n",
        tmp_path,
    )
    assert [scope.condition(c) for c in ("P", "R", "A", "O", "N", "Loop", "Missing")] == [
        True,
        None,
        None,
        True,
        None,
        None,
        None,
    ]
    assert scope.resolve({"Fn::If": ["P", "a", "b"]}) == (
        "a",
        [
            "condition P",
        ],
    )
    with pytest.raises(Unresolved):
        scope.resolve({"Fn::If": ["R", "a", "b"]})
    assert Scope().condition("P") is None  # no template, nothing known


def test_standalone_ingress_from_a_parameter_stops_unknown(tmp_path: Path) -> None:
    text = (
        "Parameters:\n  Admin:\n    Type: String\n    Default: 0.0.0.0/0\n"
        "Resources:\n  G:\n    Type: AWS::EC2::SecurityGroup\n"
        "    Properties:\n      GroupDescription: g\n"
        "  GIn:\n    Type: AWS::EC2::SecurityGroupIngress\n    Properties:\n"
        "      GroupId: !Ref G\n      IpProtocol: tcp\n      FromPort: 22\n      ToPort: 22\n"
        "      CidrIp: !Ref Admin\n"
    )
    t = parse(text, tmp_path / "g.yaml")
    res = cfn.CfnResource("s", "G", cfn.SG_TYPE, t, t.resources["G"], 6, Scope(t, "s"))
    sg = cfn.parse_sg(res)
    assert sg.rules() == [Rule("0.0.0.0/0", 22, 22, "tcp")]  # GroupId's !Ref isn't a rule field
    with pytest.raises(StageStop) as exc:
        render_sg(sg, Synthesis(sg.rules(), [], [Rule("192.0.2.1/32", 22, 22, "tcp")], [], [], []))
    assert exc.value.unknown and "GIn" in exc.value.reason and "parameter Admin" in exc.value.reason
