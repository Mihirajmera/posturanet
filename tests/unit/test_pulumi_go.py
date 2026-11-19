"""Pulumi Go programs: literal reading, locate, edits, validation, contract checks."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from posturanet import pulumi
from posturanet.cdk.source import mask
from posturanet.contracts import dump_contract
from posturanet.evidence import FileSource
from posturanet.gate import check_source
from posturanet.models import CheckResult
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix, run_fix_full
from posturanet.pulumi import source
from posturanet.pulumi.stack import is_pulumi
from posturanet.synth.sg_rules import Rule
from posturanet.synth.sg_z3 import Synthesis

FIX = Path(__file__).resolve().parents[1] / "fixtures"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
SG = FIX / "findings" / "sg_ssh_open.json"
S3 = FIX / "findings" / "s3_assets_public.json"
IAM = FIX / "findings" / "iam21_app.json"
FLOWS = FIX / "flows" / "bastion_90d.json"


@pytest.fixture
def go(tmp_path: Path) -> Path:
    return Path(shutil.copytree(FIX / "pulumi" / "go-program", tmp_path / "go"))


def _ctx(evidence: Path, **kw: Any) -> Context:
    return Context(evidence=FileSource(evidence), clock=lambda: NOW, **kw)


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text("utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), "utf-8", newline="")


def _stop(record: Any, stage: str) -> str:
    assert record.result == "STOPPED", record.stages
    return str(next(s for s in record.stages if s.name == stage).summary)


def _lit(text: str) -> Any:
    call = f'x, err := s3.NewThing(ctx, "n", &s3.ThingArgs{{V: {text}}})\n'
    (c,) = source.scan(Path("x.go"), call, "n", "Thing")
    return source.props(c).plain()["v"]


def test_literal_shapes() -> None:
    assert _lit('pulumi.String("x")') == "x" and _lit("pulumi.IntPtr(-1)") == -1
    assert _lit("pulumi.Bool(true)") is True
    assert _lit('pulumi.StringArray{pulumi.String("a"), pulumi.String("b")}') == ["a", "b"]
    assert _lit('&ec2.FooArgs{CidrBlocks: pulumi.StringArray{}, Ipv6Thing: pulumi.Int(2)}') == {
        "cidrBlocks": [], "ipv6Thing": 2
    }  # fmt: skip
    assert _lit('pulumi.String(`{"Version": "2012-10-17", "A": ["x"]}`)') == {
        "Version": "2012-10-17", "A": ["x"]
    }  # fmt: skip
    assert _lit("pulumi.String(`plain`)") == "plain"
    for computed in ("adminCidr", 'pulumi.String("a\\"b")', "pulumi.String(name)",
                     'pulumi.Sprintf("%s", x)', "pulumi.Bool(cfg.RequireBool(\"b\"))",
                     "&ec2.FooArgs{pulumi.Int(1)}", "pulumi.String('x')",
                     "pulumi.StringMap{}"):  # fmt: skip
        assert source.has_computed(_lit(computed)), computed


def test_go_mask() -> None:
    text = 'a := `C:\\` // "x\n/* ( */ b := "q\\"(" + \'(\''
    masked = mask(text, "go")
    assert "(" not in masked and masked.count("\n") == 1 and len(masked) == len(text)


def test_commented_or_unqualified_calls_are_never_matched(tmp_path: Path) -> None:
    f = tmp_path / "main.go"
    f.write_text(
        '// ec2.NewSecurityGroup(ctx, "sg", nil)\n'
        's := "ec2.NewSecurityGroup(ctx, \\"sg\\", nil)"\n'
        'NewSecurityGroup(ctx, "sg", nil)\n'
        'ec2.NewSecurityGroupRule(ctx, "sg", nil)\n'
        "ec2.NewSecurityGroup(ctx, `sg`, nil)\n",
        "utf-8",
    )
    assert source.find([f], "sg", "SecurityGroup", "ec2") == []
    f.write_text(f.read_text("utf-8") + 'sg, _ := ec2.NewSecurityGroup(ctx, "sg", nil)\n', "utf-8")
    (hit,) = source.find([f], "sg", "SecurityGroup", "ec2")
    assert (hit.line, hit.var) == (6, "sg")


def test_detection_and_locate(go: Path) -> None:
    assert is_pulumi(go, load_config(go)[0])
    (go / "main_test.go").write_text('ec2.NewSecurityGroup(ctx, "bastion-sg", nil)\n', "utf-8")
    record = run_fix(str(SG), go, load_config(go)[0], Context(clock=lambda: NOW))
    assert record.result == "DRY RUN", record.stages
    loc = record.location
    assert loc is not None and (loc.file, loc.line, loc.owners) == ("main.go", 12,
                                                                    ["@acme/platform"])  # fmt: skip
    assert any("(Go, name 'bastion-sg')" in r for r in loc.reasoning)


# --- fixes


def test_sg_fix(go: Path) -> None:
    record, proposal = run_fix_full(str(SG), go, load_config(go)[0], _ctx(FLOWS))
    assert record.diff is not None and proposal is not None, record.stages
    new = record.diff.files[0].new_content
    assert (
        '\t\t\t\t&ec2.SecurityGroupIngressArgs{Protocol: pulumi.String("tcp"), FromPort: '
        "pulumi.Int(22), ToPort: pulumi.Int(22), CidrBlocks: pulumi.StringArray{pulumi.String("
        '"10.0.4.12/32")}, Description: pulumi.String("SSH from anywhere")},\n'
    ) in new
    assert new.count("&ec2.SecurityGroupIngressArgs{") == 5 and '"0.0.0.0/0")}, D' not in new
    assert all(c.result is CheckResult.PASS for c in proposal.report.checks if c.required)


def test_standalone_rule_and_empty_list(go: Path) -> None:
    web = _target(go, "web-sg")
    one = Synthesis([Rule("0.0.0.0/0", 443, 443, "tcp")], [], [Rule("10.0.1.0/24", 443, 443, "tcp")],
                    [], [], [])  # fmt: skip
    assert 'CidrIpv4:        pulumi.String("10.0.1.0/24"),' in (
        pulumi.sg_diff(go, web, one).files[0].new_content
    )
    # both inline entries open, both removed: an empty array of the same type
    _edit(go / "main.go", 'pulumi.String("10.0.0.0/16")', 'pulumi.String("0.0.0.0/0")')

    def wide(r: dict[str, Any]) -> None:
        for side in ("inputs", "outputs"):
            r["bastion-sg"][side]["ingress"][1]["cidrBlocks"] = ["0.0.0.0/0"]

    _export(go, wide)
    t = _target(go, "bastion-sg")
    gone = Synthesis([Rule("0.0.0.0/0", 22, 22, "tcp"), Rule("0.0.0.0/0", 9100, 9100, "tcp")],
                     [], [], [], [], [])  # fmt: skip
    assert "Ingress: ec2.SecurityGroupIngressArray{},\n" in (
        pulumi.sg_diff(go, t, gone).files[0].new_content
    )


def _export(repo: Path, change: Any) -> None:
    path = repo / "stack-export.json"
    doc = json.loads(path.read_text("utf-8"))
    change({r["urn"].rsplit("::", 1)[-1]: r for r in doc["deployment"]["resources"]})
    path.write_text(json.dumps(doc), "utf-8")


def _target(repo: Path, name: str) -> pulumi.PulumiTarget:
    config = load_config(repo)[0]
    t = pulumi.resolve_address(
        repo, config, f"pulumi.prod.{name}", pulumi.load_export(repo, config, None)
    )
    assert not isinstance(t, str), t
    return t


def test_s3_fix(go: Path) -> None:
    record, _ = run_fix_full(str(S3), go, load_config(go)[0], _ctx(FIX / "s3/public_unused.json"))
    assert record.diff is not None, record.stages
    udiff = record.diff.files[0].unified_diff
    assert "+\t\tBlockPublicAcls:  pulumi.Bool(true),\n" in udiff
    assert "+\t\tBlockPublicPolicy: pulumi.Bool(true),\n+\t\tRestrictPublicBuckets: " in udiff


def test_iam_fix_in_raw_json_and_single_action(go: Path) -> None:
    record, _ = run_fix_full(str(IAM), go, load_config(go)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    assert (
        '"Action": [\n\t\t\t\t\t"ec2:DescribeInstances",\n\t\t\t\t\t"ec2:DescribeVolumes",\n'
        '\t\t\t\t\t"logs:CreateLogStream"\n\t\t\t\t],' in record.diff.files[0].new_content
    )
    store = go / "storage.go"
    _edit(store, '"Action": [\n\t\t\t\t\t"ec2:*",\n\t\t\t\t\t"logs:*"\n\t\t\t\t],',
          '"Action": "ec2:*",')  # fmt: skip

    def one(r: dict[str, Any]) -> None:
        for side in ("inputs", "outputs"):
            doc = json.loads(r["app"][side]["policy"])
            doc["Statement"][0]["Action"] = "ec2:*"
            r["app"][side]["policy"] = json.dumps(doc)

    _export(go, one)
    record, _ = run_fix_full(str(IAM), go, load_config(go)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    assert '"Action": ["ec2:DescribeInstances", "ec2:DescribeVolumes"],' in (
        record.diff.files[0].new_content
    )


# --- stops


@pytest.mark.parametrize(
    ("old", "new", "says"),
    [
        ('pulumi.StringArray{pulumi.String("0.0.0.0/0")}', "pulumi.StringArray{adminCidr}",
         "not a literal"),
        ("Ingress: ec2.SecurityGroupIngressArray{", "Ingress: rules, X: ec2.SecurityGroupIngressArray{",
         "not a literal list"),
        ("SecurityGroupId: web.ID(),", "SecurityGroupId: bastionSg.ID(),",
         "points at a different group"),
        ('vpc.NewSecurityGroupIngressRule(ctx, "web-https",',
         "vpc.NewSecurityGroupIngressRule(ctx, ruleName,", "computed name"),
    ],
)  # fmt: skip
def test_sg_stops_unknown(go: Path, old: str, new: str, says: str) -> None:
    _edit(go / "main.go", old, new)
    record = run_fix(str(SG), go, load_config(go)[0], _ctx(FLOWS))
    assert says in _stop(record, "locate") and record.exit_code == 3


# --- validation and the gate


def test_validation_fails_an_edit_outside_the_target(go: Path) -> None:
    config = load_config(go)[0]
    _, proposal = run_fix_full(str(SG), go, config, _ctx(FLOWS))
    assert proposal is not None
    t = _target(go, "bastion-sg")
    f = proposal.diff.files[0]
    bad = f.model_copy(
        update={"new_content": f.new_content.replace('String("web")', 'String("x")')}
    )
    report = pulumi.validate_sg(
        go, t, proposal.diff.model_copy(update={"files": [bad]}), proposal.synthesis,
        proposal.contract, "EC2.19", config,
    )  # fmt: skip
    assert next(c for c in report.checks if c.id == "program_scope").result is CheckResult.FAIL


def test_contract_check_source_on_go(go: Path) -> None:
    config = load_config(go)[0]
    _, proposal = run_fix_full(str(SG), go, config, _ctx(FLOWS))
    assert proposal is not None
    cpath = go / proposal.contract_file
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(dump_contract(proposal.contract), "utf-8")
    assert check_source(go, config).status == "BLOCK"
    main = go / "main.go"
    main.write_bytes(proposal.diff.files[0].new_content.encode("utf-8"))
    assert check_source(go, config, [main]).status == "PASS"
    _edit(main, "\n\t\tif err := storage", '\n\t\tvpc.NewSecurityGroupIngressRule(ctx, "x", '
          '&vpc.SecurityGroupIngressRuleArgs{SecurityGroupId: bastionSg.ID(), IpProtocol: '
          'pulumi.String("-1"), CidrIpv4: pulumi.String("0.0.0.0/0")})\n\t\tif err := storage')  # fmt: skip
    assert check_source(go, config, [main]).status == "UNKNOWN"
