"""Pulumi C# programs: literal reading, locate, edits, validation, contract checks."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from posturanet import pulumi
from posturanet.cdk.source import items, mask
from posturanet.contracts import dump_contract
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.gate import check_source
from posturanet.models import CheckResult
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix, run_fix_full
from posturanet.pulumi import source
from posturanet.pulumi.stack import is_pulumi, program
from posturanet.synth.sg_rules import Rule
from posturanet.synth.sg_z3 import Synthesis

FIX = Path(__file__).resolve().parents[1] / "fixtures"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
SG = FIX / "findings" / "sg_ssh_open.json"
S3 = FIX / "findings" / "s3_assets_public.json"
IAM = FIX / "findings" / "iam21_app.json"
FLOWS = FIX / "flows" / "bastion_90d.json"


@pytest.fixture
def cs(tmp_path: Path) -> Path:
    return Path(shutil.copytree(FIX / "pulumi" / "cs-program", tmp_path / "cs"))


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
    call = f'using Pulumi.Aws.S3;\nnew Thing("n", new() {{ V = {text} }});\n'
    (c,) = source.scan(Path("x.cs"), call, "n", "Thing")
    return source.props(c).plain()["v"]


def test_literal_shapes() -> None:
    assert _lit('"x"') == "x" and _lit("-1") == -1 and _lit("true") is True
    assert _lit('new[] { "a", "b" }') == ["a", "b"]
    assert _lit('new string[] { "a" }') == _lit('new InputList<string> { "a" }') == ["a"]
    assert _lit('new List<string>() { "a", }') == ["a"]
    assert _lit("new Aws.Ec2.Inputs.FooArgs { CidrBlocks = new[] { \"c\" }, Ipv6Thing = 2 }") == {
        "cidrBlocks": ["c"], "ipv6Thing": 2
    }  # fmt: skip
    assert _lit('JsonSerializer.Serialize(new Dictionary<string, object?> { ["A"] = new[] '
                '{ "x" }, ["V"] = "1" })') == {"A": ["x"], "V": "1"}  # fmt: skip
    for computed in ("adminCidr", '@"0.0.0.0/0"', '$"{x}"', '"a\\"b"', "'c'",
                     'config.RequireBoolean("b")', "new { A = 1 }", "new() { [\"A\"] = 1 }",
                     'new Dictionary<string, object?> { { "A", 1 } }', "new[] { x }",
                     "JsonSerializer.Serialize(doc)", '"""raw"""'):  # fmt: skip
        assert source.has_computed(_lit(computed)), computed


def test_cs_mask() -> None:
    text = 'var a = @"C:\\ ""(""" // (\n/* ( */ var b = """ ( " """; var c = \'(\';'
    masked = mask(text, "cs")
    assert "(" not in masked and masked.count("\n") == 1 and len(masked) == len(text)
    generic = 'new Dictionary<string, List<int?>>() { ["a"] = 1, ["b"] = 2 }'
    m = mask(generic, "cs")
    assert len(items(m, m.index("{"), m.rindex("}"))) == 2
    assert len(items(m, m.index("("), m.index(")"))) == 0  # the type's comma is blanked


def test_bare_classes_need_their_using(tmp_path: Path) -> None:
    f = tmp_path / "Program.cs"
    f.write_text(
        '// new SecurityGroup("sg", null);\n'
        'var s = "new SecurityGroup(\\"sg\\", null)";\n'
        'new SecurityGroup("sg", null);\n'
        'new Aws.Ec2.SecurityGroupRule("sg", null);\n',
        "utf-8",
    )
    assert source.find([f], "sg", "SecurityGroup", "ec2") == []
    f.write_text("using Pulumi.Aws.Ec2;\n" + f.read_text("utf-8"), "utf-8")
    (hit,) = source.find([f], "sg", "SecurityGroup", "ec2")
    assert hit.line == 4
    f.write_text('var sg = new Pulumi.Aws.Ec2.SecurityGroup("sg", null);\n', "utf-8")
    (hit,) = source.find([f], "sg", "SecurityGroup", "ec2")
    assert hit.var == "sg"


def test_detection_files_and_locate(cs: Path) -> None:
    config = load_config(cs)[0]
    assert is_pulumi(cs, config)
    for d in ("bin", "obj"):
        (cs / d).mkdir()
        (cs / d / "Gen.cs").write_text('new SecurityGroup("bastion-sg", null);\n', "utf-8")
    assert [p.name for p in program(cs, config).files()] == ["Program.cs", "Storage.cs"]
    record = run_fix(str(SG), cs, config, Context(clock=lambda: NOW))
    assert record.result == "DRY RUN", record.stages
    loc = record.location
    assert loc is not None and (loc.file, loc.line, loc.owners) == ("Program.cs", 9,
                                                                    ["@acme/platform"])  # fmt: skip
    assert any("(C#, name 'bastion-sg')" in r for r in loc.reasoning)


# --- fixes


def test_sg_fix(cs: Path) -> None:
    record, proposal = run_fix_full(str(SG), cs, load_config(cs)[0], _ctx(FLOWS))
    assert record.diff is not None and proposal is not None, record.stages
    new = record.diff.files[0].new_content
    assert (
        '            new Aws.Ec2.Inputs.SecurityGroupIngressArgs { Protocol = "tcp", FromPort = 22, '
        'ToPort = 22, CidrBlocks = new[] { "10.0.4.12/32" }, Description = "SSH from anywhere" '
        "},\n"
    ) in new
    assert new.count("SecurityGroupIngressArgs {") == 5 and '"0.0.0.0/0" }, D' not in new
    assert all(c.result is CheckResult.PASS for c in proposal.report.checks if c.required)


def test_standalone_rule_and_empty_array(cs: Path) -> None:
    web = _target(cs, "web-sg")
    one = Synthesis([Rule("0.0.0.0/0", 443, 443, "tcp")], [], [Rule("10.0.1.0/24", 443, 443, "tcp")],
                    [], [], [])  # fmt: skip
    assert 'CidrIpv4 = "10.0.1.0/24",' in pulumi.sg_diff(cs, web, one).files[0].new_content
    # both inline entries open, both removed: `new[] { }` has no type, so it stops
    _edit(cs / "Program.cs", '"10.0.0.0/16"', '"0.0.0.0/0"')
    path = cs / "stack-export.json"
    doc = json.loads(path.read_text("utf-8"))
    sg = next(r for r in doc["deployment"]["resources"] if r["urn"].endswith("::bastion-sg"))
    for side in ("inputs", "outputs"):
        sg[side]["ingress"][1]["cidrBlocks"] = ["0.0.0.0/0"]
    path.write_text(json.dumps(doc), "utf-8")
    gone = Synthesis([Rule("0.0.0.0/0", 22, 22, "tcp"), Rule("0.0.0.0/0", 9100, 9100, "tcp")],
                     [], [], [], [], [])  # fmt: skip
    with pytest.raises(StageStop, match="empty the C# list by hand"):
        pulumi.sg_diff(cs, _target(cs, "bastion-sg"), gone)


def _target(repo: Path, name: str) -> pulumi.PulumiTarget:
    config = load_config(repo)[0]
    t = pulumi.resolve_address(
        repo, config, f"pulumi.prod.{name}", pulumi.load_export(repo, config, None)
    )
    assert not isinstance(t, str), t
    return t


def test_s3_fix(cs: Path) -> None:
    record, _ = run_fix_full(str(S3), cs, load_config(cs)[0], _ctx(FIX / "s3/public_unused.json"))
    assert record.diff is not None, record.stages
    udiff = record.diff.files[0].unified_diff
    assert "+            BlockPublicAcls = true,\n" in udiff
    assert (
        "+            BlockPublicPolicy = true,\n+            RestrictPublicBuckets = true,"
        in udiff
    )


def test_iam_fix_keeps_the_array_layout(cs: Path) -> None:
    record, _ = run_fix_full(str(IAM), cs, load_config(cs)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    ind = " " * 28
    assert (
        f'["Action"] = new[]\n{ind[4:]}{{\n{ind}"ec2:DescribeInstances",\n'
        f'{ind}"ec2:DescribeVolumes",\n{ind}"logs:CreateLogStream",\n{ind[4:]}}},'
    ) in record.diff.files[0].new_content


# --- stops


@pytest.mark.parametrize(
    ("old", "new", "says"),
    [
        ('new[] { "0.0.0.0/0" }', "new[] { adminCidr }", "not a literal"),
        ("Ingress = new[]", "Ingress = rules,\n        Tags = new[]", "not a literal list"),
        ("SecurityGroupId = web.Id,", "SecurityGroupId = bastionSg.Id,",
         "points at a different group"),
        ('new Aws.Vpc.SecurityGroupIngressRule("web-https",',
         "new Aws.Vpc.SecurityGroupIngressRule(ruleName,", "computed name"),
        ('new SecurityGroup("bastion-sg", new()', 'new SecurityGroup("bastion-sg", args, new()',
         "not a literal object"),
    ],
)  # fmt: skip
def test_sg_stops_unknown(cs: Path, old: str, new: str, says: str) -> None:
    _edit(cs / "Program.cs", old, new)
    record = run_fix(str(SG), cs, load_config(cs)[0], _ctx(FLOWS))
    assert says in _stop(record, "locate") and record.exit_code == 3


# --- validation and the gate


def test_contract_check_source_on_cs(cs: Path) -> None:
    config = load_config(cs)[0]
    _, proposal = run_fix_full(str(SG), cs, config, _ctx(FLOWS))
    assert proposal is not None
    cpath = cs / proposal.contract_file
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(dump_contract(proposal.contract), "utf-8")
    assert check_source(cs, config).status == "BLOCK"
    main = cs / "Program.cs"
    main.write_bytes(proposal.diff.files[0].new_content.encode("utf-8"))
    assert check_source(cs, config, [main]).status == "PASS"
    _edit(main, "\n    Storage.Create();", '\n    new Aws.Vpc.SecurityGroupIngressRule("x", new() '
          '{ SecurityGroupId = bastionSg.Id, IpProtocol = "-1", CidrIpv4 = "0.0.0.0/0" });'
          "\n    Storage.Create();")  # fmt: skip
    assert check_source(cs, config, [main]).status == "UNKNOWN"
