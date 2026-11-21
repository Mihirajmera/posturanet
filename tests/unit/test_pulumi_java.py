"""Pulumi Java programs: literal reading, locate, edits, validation, contract checks."""

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
from posturanet.pulumi.stack import is_pulumi, program
from posturanet.synth.sg_rules import Rule
from posturanet.synth.sg_z3 import Synthesis

FIX = Path(__file__).resolve().parents[1] / "fixtures"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
SG = FIX / "findings" / "sg_ssh_open.json"
S3 = FIX / "findings" / "s3_assets_public.json"
IAM = FIX / "findings" / "iam21_app.json"
FLOWS = FIX / "flows" / "bastion_90d.json"
SRC = Path("src/main/java/acme")


@pytest.fixture
def java(tmp_path: Path) -> Path:
    return Path(shutil.copytree(FIX / "pulumi" / "java-program", tmp_path / "java"))


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
    call = (
        f'import com.pulumi.aws.s3.Thing;\nnew Thing("n", ThingArgs.builder().v({text}).build());\n'
    )
    (c,) = source.scan(Path("X.java"), call, "n", "Thing")
    return source.props(c).plain()["v"]


def test_literal_shapes() -> None:
    assert _lit('"x"') == "x" and _lit("-1") == -1 and _lit("true") is True
    assert _lit('List.of("a", "b")') == _lit('Arrays.asList("a", "b")') == ["a", "b"]
    assert _lit("List.of()") == []
    assert _lit('Map.of("k", "v", "n", 2)') == {"k": "v", "n": 2}
    assert _lit('FooArgs.builder().cidrBlocks("c", "d").ipv6Thing(2).build()') == {
        "cidrBlocks": ["c", "d"], "ipv6Thing": 2
    }  # fmt: skip
    assert _lit('FooArgs.builder().cidrBlocks(List.of("c")).build()') == {"cidrBlocks": ["c"]}
    assert _lit('serializeJson(jsonObject(jsonProperty("A", jsonArray("x")), '
                'jsonProperty("V", "1")))') == {"A": ["x"], "V": "1"}  # fmt: skip
    for computed in ("adminCidr", '"a\\"b"', "'c'", '"a" + "b"', '"""\n  raw"""',
                     'config.requireBoolean("b")', "FooArgs.builder().a(1).a(2).build()",
                     "FooArgs.builder().a(1)", "FooArgs.builder().a(1, 2).build()",
                     'Map.of(key, "v")', 'jsonObject(jsonProperty("A", 1, 2))',
                     'jsonObject(jsonProperty("A", 1), jsonProperty("A", 2))',
                     "serializeJson(doc)", 'List.of(x, "a")', "FooArgs.builder().build().a()",
                     "args"):  # fmt: skip
        assert source.has_computed(_lit(computed)), computed


def test_java_mask() -> None:
    text = 'var a = "(\\"("; // (\n/* ( */ var b = """\n ( " \n"""; var c = \'(\';'
    masked = mask(text, "java")
    assert "(" not in masked and masked.count("\n") == 3 and len(masked) == len(text)


def test_bare_classes_need_their_import(tmp_path: Path) -> None:
    f = tmp_path / "App.java"
    f.write_text(
        "import com.pulumi.aws.ec2.SecurityGroupArgs;\n"
        "import com.pulumi.aws.vpc.SecurityGroup;\n"
        '// new SecurityGroup("sg", null);\n'
        'new SecurityGroup("sg", null);\n',
        "utf-8",
    )
    assert source.find([f], "sg", "SecurityGroup", "ec2") == []  # vpc's, not ec2's
    f.write_text("import com.pulumi.aws.ec2.*;\n" + f.read_text("utf-8"), "utf-8")
    (hit,) = source.find([f], "sg", "SecurityGroup", "ec2")
    assert hit.line == 5
    f.write_text('final var sg = new com.pulumi.aws.ec2.SecurityGroup("sg", null);\n', "utf-8")
    (hit,) = source.find([f], "sg", "SecurityGroup", "ec2")
    assert hit.var == "sg"


def test_detection_files_and_locate(java: Path) -> None:
    config = load_config(java)[0]
    assert is_pulumi(java, config)
    for d in ("build", "target", "src/test/java"):
        (java / d).mkdir(parents=True)
        (java / d / "Gen.java").write_text('new SecurityGroup("bastion-sg", null);\n', "utf-8")
    assert [p.name for p in program(java, config).files()] == ["App.java", "Storage.java"]
    record = run_fix(str(SG), java, config, Context(clock=lambda: NOW))
    assert record.result == "DRY RUN", record.stages
    loc = record.location
    assert loc is not None and (loc.file, loc.line) == ((SRC / "App.java").as_posix(), 18)
    assert loc.owners == ["@acme/platform"]
    assert any("(Java, name 'bastion-sg')" in r for r in loc.reasoning)


# --- fixes


def test_sg_fix(java: Path) -> None:
    record, proposal = run_fix_full(str(SG), java, load_config(java)[0], _ctx(FLOWS))
    assert record.diff is not None and proposal is not None, record.stages
    new = record.diff.files[0].new_content
    entry = (
        'SecurityGroupIngressArgs.builder().protocol("tcp").fromPort(22).toPort(22)'
        '.cidrBlocks("{}").description("SSH from anywhere").build(),\n'
    )
    pad = " " * 16
    assert pad + entry.format("10.0.4.12/32") + pad + entry.format("10.0.4.37/32") in new
    assert new.count("SecurityGroupIngressArgs.builder()") == 5 and "0.0.0.0/0" not in new.split(
        "web-sg"
    )[0]  # fmt: skip
    assert all(c.result is CheckResult.PASS for c in proposal.report.checks if c.required)


def test_standalone_rule_and_empty_varargs(java: Path) -> None:
    web = _target(java, "web-sg")
    one = Synthesis([Rule("0.0.0.0/0", 443, 443, "tcp")], [], [Rule("10.0.1.0/24", 443, 443, "tcp")],
                    [], [], [])  # fmt: skip
    assert '.cidrIpv4("10.0.1.0/24")' in pulumi.sg_diff(java, web, one).files[0].new_content
    # both inline entries open, both removed: `.ingress()` with no items
    _edit(java / SRC / "App.java", '"10.0.0.0/16"', '"0.0.0.0/0"')
    path = java / "stack-export.json"
    doc = json.loads(path.read_text("utf-8"))
    sg = next(r for r in doc["deployment"]["resources"] if r["urn"].endswith("::bastion-sg"))
    for side in ("inputs", "outputs"):
        sg[side]["ingress"][1]["cidrBlocks"] = ["0.0.0.0/0"]
    path.write_text(json.dumps(doc), "utf-8")
    gone = Synthesis([Rule("0.0.0.0/0", 22, 22, "tcp"), Rule("0.0.0.0/0", 9100, 9100, "tcp")],
                     [], [], [], [], [])  # fmt: skip
    new = pulumi.sg_diff(java, _target(java, "bastion-sg"), gone).files[0].new_content
    assert "            .ingress(\n                )\n" in new


def _target(repo: Path, name: str) -> pulumi.PulumiTarget:
    config = load_config(repo)[0]
    t = pulumi.resolve_address(
        repo, config, f"pulumi.prod.{name}", pulumi.load_export(repo, config, None)
    )
    assert not isinstance(t, str), t
    return t


def test_s3_fix_adds_setters_before_build(java: Path) -> None:
    record, _ = run_fix_full(
        str(S3), java, load_config(java)[0], _ctx(FIX / "s3/public_unused.json")
    )
    assert record.diff is not None, record.stages
    assert (
        "            .blockPublicAcls(true)\n            .ignorePublicAcls(true)\n"
        "            .blockPublicPolicy(true)\n            .restrictPublicBuckets(true)\n"
        "            .build());"
    ) in record.diff.files[0].new_content
    # setters on one line stay on one line
    _edit(java / SRC / "Storage.java", "\n            .ignorePublicAcls(true)\n            .build",
          ".ignorePublicAcls(true).build")  # fmt: skip
    record, _ = run_fix_full(
        str(S3), java, load_config(java)[0], _ctx(FIX / "s3/public_unused.json")
    )
    assert record.diff is not None, record.stages
    assert (
        ".ignorePublicAcls(true).blockPublicPolicy(true).restrictPublicBuckets(true).build());"
    ) in record.diff.files[0].new_content


def test_iam_fix_keeps_the_layout_and_single_action(java: Path) -> None:
    record, _ = run_fix_full(str(IAM), java, load_config(java)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    ind = " " * 28
    assert (
        f'jsonProperty("Action", jsonArray(\n{ind}"ec2:DescribeInstances",\n'
        f'{ind}"ec2:DescribeVolumes",\n{ind}"logs:CreateLogStream"\n{ind[4:]})),'
    ) in record.diff.files[0].new_content
    store = java / SRC / "Storage.java"
    _edit(store, f'jsonArray(\n{ind}"ec2:*",\n{ind}"logs:*"\n{ind[4:]})', '"ec2:*"')
    path = java / "stack-export.json"
    doc = json.loads(path.read_text("utf-8"))
    app = next(r for r in doc["deployment"]["resources"] if r["urn"].endswith("::app"))
    for side in ("inputs", "outputs"):
        p = json.loads(app[side]["policy"])
        p["Statement"][0]["Action"] = "ec2:*"
        app[side]["policy"] = json.dumps(p)
    path.write_text(json.dumps(doc), "utf-8")
    record, _ = run_fix_full(str(IAM), java, load_config(java)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    assert 'jsonProperty("Action", jsonArray("ec2:DescribeInstances", "ec2:DescribeVolumes")),' in (
        record.diff.files[0].new_content
    )


# --- stops


@pytest.mark.parametrize(
    ("old", "new", "says"),
    [
        ('.cidrBlocks("0.0.0.0/0")', ".cidrBlocks(adminCidr)", "not a literal"),
        (".ingress(\n", ".ingress(rules)\n            .egress(\n", "ingress entry 1 of"),
        (".securityGroupId(web.id())", ".securityGroupId(bastionSg.id())",
         "points at a different group"),
        ('new SecurityGroupIngressRule("web-https",', "new SecurityGroupIngressRule(ruleName,",
         "computed name"),
        ('new SecurityGroup("bastion-sg", SecurityGroupArgs.builder()',
         'new SecurityGroup("bastion-sg", args.toBuilder()', "not a literal object"),
    ],
)  # fmt: skip
def test_sg_stops_unknown(java: Path, old: str, new: str, says: str) -> None:
    _edit(java / SRC / "App.java", old, new)
    record = run_fix(str(SG), java, load_config(java)[0], _ctx(FLOWS))
    assert says in _stop(record, "locate") and record.exit_code == 3


# --- the gate


def test_contract_check_source_on_java(java: Path) -> None:
    config = load_config(java)[0]
    _, proposal = run_fix_full(str(SG), java, config, _ctx(FLOWS))
    assert proposal is not None
    cpath = java / proposal.contract_file
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(dump_contract(proposal.contract), "utf-8")
    assert check_source(java, config).status == "BLOCK"
    main = java / SRC / "App.java"
    main.write_bytes(proposal.diff.files[0].new_content.encode("utf-8"))
    assert check_source(java, config, [main]).status == "PASS"
    _edit(main, "\n        Storage.create();", '\n        new SecurityGroupIngressRule("x", '
          'SecurityGroupIngressRuleArgs.builder().securityGroupId(bastionSg.id()).ipProtocol("-1")'
          '.cidrIpv4("0.0.0.0/0").build());\n        Storage.create();')  # fmt: skip
    assert check_source(java, config, [main]).status == "UNKNOWN"
