"""CloudFormation security groups whose rules live in AWS::EC2::SecurityGroupIngress resources."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from posturanet import cfn
from posturanet.cfn.edit import render_sg
from posturanet.cfn.template import parse, value
from posturanet.contracts import dump_contract
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.gate import check_source
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix_full
from posturanet.synth.sg_rules import Rule
from posturanet.synth.sg_z3 import Synthesis

FIX = Path(__file__).resolve().parents[1] / "fixtures"
SG = FIX / "findings" / "sg_ssh_open.json"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
SSH_INLINE = (
    "        - IpProtocol: tcp\n          FromPort: 22\n          ToPort: 22\n"
    "          CidrIp: 0.0.0.0/0\n          Description: SSH from anywhere\n"
)
SSH_RESOURCE = """
  # SSH lives in its own resource
  BastionSSH:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: !GetAtt BastionSG.GroupId
      IpProtocol: tcp
      FromPort: 22
      ToPort: 22
      CidrIp: 0.0.0.0/0
      Description: SSH from anywhere
"""
TWO = [Rule("192.0.2.10/32", 22, 22, "tcp"), Rule("198.51.100.0/24", 22, 22, "tcp")]


def _sg(text: str, tmp_path: Path, name: str = "t.yaml", lid: str = "SG") -> cfn.CfnSecurityGroup:
    t = parse(text, tmp_path / name)
    return cfn.parse_sg(cfn.CfnResource("s", lid, cfn.SG_TYPE, t, t.resources[lid], 2))


def _render(sg: cfn.CfnSecurityGroup, added: list[Rule]) -> str:
    kept = [r for r in sg.rules() if not r.is_world]
    return render_sg(sg, Synthesis([r for r in sg.rules() if r.is_world], kept, added, [], [], []))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """The basic CloudFormation fixture with BastionSG's SSH rule moved to its own resource."""
    dst = tmp_path / "repo"
    shutil.copytree(FIX / "cfn" / "basic", dst)
    path = dst / "templates" / "network.yaml"
    text = path.read_text("utf-8").replace("\r\n", "\n")
    assert SSH_INLINE in text
    text = text.replace(SSH_INLINE, "").replace("\nOutputs:", SSH_RESOURCE + "\nOutputs:")
    path.write_bytes(text.encode("utf-8"))
    return dst


def test_full_fix_edits_the_standalone_resource(repo: Path) -> None:
    config, _ = load_config(repo)
    ctx = Context(evidence=FileSource(FIX / "flows/bastion_90d.json"), clock=lambda: NOW)
    record, proposal = run_fix_full(str(SG), repo, config, ctx)
    assert record.result == "DRY RUN", record.stages
    assert proposal is not None
    removed = [ln for ln in proposal.diff.files[0].unified_diff.splitlines() if ln[:1] == "-"]
    assert removed[1:] == ["-      CidrIp: 0.0.0.0/0"]
    new = proposal.diff.files[0].new_content.replace("\r\n", "\n")
    assert "      CidrIp: 10.0.4.12/32\n      Description: SSH from anywhere\n" in new
    assert "# SSH lives in its own resource" in new
    checks = {c.id: c.result.value for c in proposal.report.checks}
    assert checks["template_scope"] == checks["invariants"] == checks["recheck"] == "pass"
    assert checks["template_matches"] == "pass"

    # contract check --source reads the standalone rule too
    cpath = repo / proposal.contract_file
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(dump_contract(proposal.contract), "utf-8")
    assert check_source(repo, config).status == "BLOCK"
    target = repo / "templates/network.yaml"
    target.write_text(proposal.diff.files[0].new_content, "utf-8")
    assert check_source(repo, config, [target]).status == "PASS"


YAML_MIXED = """Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: g
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
          Description: ssh

  # https for everyone
  Https:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: !Ref SG
      IpProtocol: tcp
      FromPort: 443
      ToPort: 443
      CidrIp: 0.0.0.0/0

  Ssh6:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId:
        Fn::GetAtt: [SG, GroupId]
      IpProtocol: tcp
      FromPort: 22
      ToPort: 22
      CidrIpv6: ::/0

  Monitoring:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: {GroupId: !Ref SG, IpProtocol: tcp, FromPort: 9100, ToPort: 9100, CidrIp: 10.0.0.0/16}

  Other:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: !Ref OtherSG
      IpProtocol: tcp
      FromPort: 22
      ToPort: 22
      CidrIp: 0.0.0.0/0

  OtherSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: other
"""


def test_mixed_yaml_inline_hosts_new_rules_and_open_resources_go(tmp_path: Path) -> None:
    sg = _sg(YAML_MIXED, tmp_path)
    assert [e.resource for e in sg.entries] == [None, "Https", "Ssh6", "Monitoring"]
    assert Rule("10.0.0.0/16", 9100, 9100, "tcp") in sg.rules()
    new = _render(sg, TWO)
    assert new == YAML_MIXED.replace(
        "          CidrIp: 0.0.0.0/0\n          Description: ssh\n",
        "          CidrIp: 192.0.2.10/32\n          Description: ssh\n"
        "        - IpProtocol: tcp\n          FromPort: 22\n          ToPort: 22\n"
        "          CidrIp: 198.51.100.0/24\n          Description: ssh\n",
    ).replace(
        YAML_MIXED[YAML_MIXED.index("  Https:") : YAML_MIXED.index("  Monitoring:")],
        "\n",
    )
    assert "# https for everyone\n\n  Monitoring:" in new  # comment kept, one blank line left
    edited = parse(new, tmp_path / "t.yaml")
    assert value(edited.resources["Other"]) == value(sg.res.template.resources["Other"])


def test_yaml_only_standalone_and_nothing_kept_drops_resources(tmp_path: Path) -> None:
    text = YAML_MIXED.replace(
        "      SecurityGroupIngress:\n"
        + YAML_MIXED.split("SecurityGroupIngress:\n")[1].split("\n\n")[0]
        + "\n",
        "",
    )
    sg = _sg(text, tmp_path)
    assert [e.resource for e in sg.entries] == ["Https", "Ssh6", "Monitoring"]
    new = _render(sg, [])
    assert "Https" not in new and "Ssh6" not in new and "Monitoring:" in new
    assert "\n\n\n" not in new


def test_standalone_host_carries_new_rules_as_copies(tmp_path: Path) -> None:
    text = YAML_MIXED.replace(
        "      SecurityGroupIngress:\n"
        + YAML_MIXED.split("SecurityGroupIngress:\n")[1].split("\n\n")[0]
        + "\n",
        "",
    )
    new = _render(_sg(text, tmp_path), TWO)
    assert (
        "  Https:\n    Type: AWS::EC2::SecurityGroupIngress\n    Properties:\n"
        "      GroupId: !Ref SG\n      IpProtocol: tcp\n      FromPort: 22\n      ToPort: 22\n"
        "      CidrIp: 192.0.2.10/32\n      Description: Observed sources kept by PosturaNet\n\n"
        "  Https2:\n    Type: AWS::EC2::SecurityGroupIngress\n    Properties:\n"
        "      GroupId: !Ref SG\n      IpProtocol: tcp\n      FromPort: 22\n      ToPort: 22\n"
        "      CidrIp: 198.51.100.0/24\n      Description: Observed sources kept by PosturaNet\n\n"
        "  Monitoring:" in new
    )
    edited = _sg(new, tmp_path)
    assert edited.rules() == sorted([*TWO, Rule("10.0.0.0/16", 9100, 9100, "tcp")])


JSON_TEMPLATE = {
    "Resources": {
        "SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"GroupDescription": "g"}},
        "Ssh": {
            "Type": "AWS::EC2::SecurityGroupIngress",
            "Properties": {
                "GroupId": {"Fn::GetAtt": ["SG", "GroupId"]},
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "CidrIpv6": "::/0",
                "Description": "ssh",
            },
        },
        "Web": {
            "Type": "AWS::EC2::SecurityGroupIngress",
            "Properties": {
                "GroupId": {"Ref": "SG"},
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "CidrIp": "0.0.0.0/0",
            },
        },
    }
}


def test_json_standalone_edit_copy_and_delete(tmp_path: Path) -> None:
    text = json.dumps(JSON_TEMPLATE, indent=2) + "\n"
    sg = _sg(text, tmp_path, "t.json")
    new = _render(sg, TWO)
    out = json.loads(new)["Resources"]
    assert set(out) == {"SG", "Ssh", "Ssh2"}
    assert out["Ssh"]["Properties"] == {
        "GroupId": {"Fn::GetAtt": ["SG", "GroupId"]},
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "Description": "ssh",
        "CidrIp": "192.0.2.10/32",
    }
    assert out["Ssh2"]["Properties"]["CidrIp"] == "198.51.100.0/24"
    assert '\n    "Ssh2": {\n      "Type"' in new  # same layout as the resource it copies
    assert _sg(new, tmp_path, "t.json").rules() == TWO


@pytest.mark.parametrize(
    ("group_id", "field"),
    [
        ("!Ref VpcSgParam", "CidrIp: 0.0.0.0/0"),
        ("!ImportValue shared-sg", "CidrIp: 0.0.0.0/0"),
        ("sg-0a91f3c2", "CidrIp: 0.0.0.0/0"),
        ("!GetAtt SG.VpcId", "CidrIp: 0.0.0.0/0"),
        ("!Ref SG", "CidrIp: !Ref OpenCidr"),
    ],
)
def test_unresolvable_group_or_intrinsic_rule_stops_unknown(
    tmp_path: Path, group_id: str, field: str
) -> None:
    text = (
        "Resources:\n  SG:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n"
        "      GroupDescription: g\n  R:\n    Type: AWS::EC2::SecurityGroupIngress\n"
        f"    Properties:\n      GroupId: {group_id}\n      IpProtocol: tcp\n"
        f"      FromPort: 22\n      ToPort: 22\n      {field}\n"
    )
    with pytest.raises(StageStop) as exc:
        _sg(text, tmp_path)
    assert exc.value.unknown


def test_drift_covers_the_standalone_resources(repo: Path) -> None:
    from test_cfn import _fake_aws

    from posturanet.cfn.validate import _drift

    config, _ = load_config(repo)
    res = cfn.resolve(repo, config, "network", "BastionSG")
    assert isinstance(res, cfn.CfnResource)
    body = (repo / "templates/network.yaml").read_text("utf-8")

    # live group = inline 9100 + standalone SSH rule, so this passes only if both are read
    assert _drift(res, _fake_aws(body), offline=False).result.value == "pass"
    drifted = body.replace(
        "      FromPort: 22\n      ToPort: 22", "      FromPort: 23\n      ToPort: 23"
    )
    assert _drift(res, _fake_aws(drifted), offline=False).result.value == "fail"
