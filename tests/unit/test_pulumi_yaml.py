"""Pulumi YAML programs: literal reading, locate, edits in the file's own layout, validation."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from posturanet import pulumi
from posturanet.contracts import dump_contract
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.gate import check_source
from posturanet.models import CheckResult
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix, run_fix_full
from posturanet.pulumi import yaml_source
from posturanet.pulumi.source import has_computed
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
def ym(tmp_path: Path) -> Path:
    return Path(shutil.copytree(FIX / "pulumi" / "yaml-program", tmp_path / "ym"))


def _ctx(evidence: Path, **kw: Any) -> Context:
    return Context(evidence=FileSource(evidence), clock=lambda: NOW, **kw)


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text("utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), "utf-8", newline="")


def _stop(record: Any, stage: str) -> str:
    assert record.result == "STOPPED", record.stages
    return str(next(s for s in record.stages if s.name == stage).summary)


def _lit(value: str) -> Any:
    text = f"resources:\n  n:\n    type: t\n    properties:\n      v: {value}\n"
    node = yaml_source.tree(text, "x").get("resources")
    assert node is not None
    v = node.value[0][1].get("properties").get("v")  # type: ignore[union-attr]
    return yaml_source.lit(text, v).plain()


def test_literal_shapes() -> None:
    assert _lit('{ a: x, b: 2, c: [true, -1], "d-e": { f: False } }') == {
        "a": "x", "b": 2, "c": [True, -1], "d-e": {"f": False}
    }  # fmt: skip
    assert _lit("'1'") == "1" and _lit("yes") == "yes"  # YAML 1.2: quoted 1 and yes are strings
    assert _lit('{ "fn::toJSON": { Version: "2012-10-17" } }') == {"Version": "2012-10-17"}
    for computed in ("${adminCidr}", "x-${a.b}", '{ "fn::secret": x }', '{ "fn::invoke": {} }',
                     "&a 1", "!Tag 1", "null", "1.5", "2012-10-17", '{ "<<": {} }'):  # fmt: skip
        assert has_computed(_lit(computed)), computed


def test_render_keeps_plain_only_when_it_reads_back() -> None:
    assert yaml_source.render("10.0.4.12/32", "") == "10.0.4.12/32"
    assert yaml_source.render("*", "") == '"*"' and yaml_source.render("true", "") == '"true"'
    assert yaml_source.render("it's", "'") == "'it''s'"
    assert yaml_source.render(["a", True, 3], '"') == '["a", true, 3]'


def test_detection_and_locate(ym: Path) -> None:
    assert is_pulumi(ym, load_config(ym)[0])
    record = run_fix(str(SG), ym, load_config(ym)[0], Context(clock=lambda: NOW))
    assert record.result == "DRY RUN", record.stages
    loc = record.location
    assert loc is not None and loc.address == "pulumi.prod.bastion-sg"
    assert (loc.file, loc.line, loc.owners) == ("Pulumi.yaml", 10, ["@acme/platform"])
    assert any("(YAML, name 'bastion-sg')" in r for r in loc.reasoning)


def test_name_property_and_main_yaml(ym: Path) -> None:
    spec = ym / "Pulumi.yaml"
    text = spec.read_text("utf-8").replace("  bastion-sg:\n", "  bastion:\n    name: bastion-sg\n")
    head, _, body = text.partition("variables:")
    spec.write_text(head + "main: src/\n", "utf-8", newline="")
    (ym / "src").mkdir()
    (ym / "src" / "Main.yaml").write_text("variables:" + body, "utf-8", newline="")
    record = run_fix(str(SG), ym, load_config(ym)[0], Context(clock=lambda: NOW))
    assert record.location is not None, record.stages
    assert (record.location.file, record.location.line) == ("src/Main.yaml", 6)


# --- fixes


def test_sg_fix_keeps_layout(ym: Path) -> None:
    record, proposal = run_fix_full(str(SG), ym, load_config(ym)[0], _ctx(FLOWS))
    assert record.result == "DRY RUN" and proposal is not None and record.diff is not None
    new = record.diff.files[0].new_content
    assert (
        "        - protocol: tcp\n          fromPort: 22\n          toPort: 22\n"
        '          cidrBlocks: ["10.0.4.12/32"]\n          description: SSH from anywhere\n'
        "        - protocol: tcp\n"
    ) in new
    assert new.count("        - protocol: tcp\n") == 4 and '0.0.0.0/0"]' not in new
    assert "        # monitoring stays as it is\n        - { protocol: tcp, fromPort: 9100" in new
    assert all(c.result is CheckResult.PASS for c in proposal.report.checks if c.required)


def test_sg_flow_item_and_standalone_rule(ym: Path) -> None:
    # SSH entry gone; the flow-style monitoring entry is open next to a private CIDR
    spec = ym / "Pulumi.yaml"
    _edit(spec, '"10.0.0.0/16"]', '"10.0.0.0/16", "0.0.0.0/0"]')
    _edit(spec, "        - protocol: tcp\n          fromPort: 22\n          toPort: 22\n"
          '          cidrBlocks: ["0.0.0.0/0"]\n          description: SSH from anywhere\n',
          "")  # fmt: skip

    def ingress(r: dict[str, Any]) -> None:
        for side in ("inputs", "outputs"):
            e = r["bastion-sg"][side]["ingress"]
            e[1]["cidrBlocks"].append("0.0.0.0/0")
            del e[0]

    _export(ym, ingress)
    t = _target(ym, "bastion-sg")
    synth = Synthesis(
        removed=[Rule("0.0.0.0/0", 9100, 9100, "tcp")], kept=[Rule("10.0.0.0/16", 9100, 9100, "tcp")],
        added=[Rule("10.0.9.9/32", 9100, 9100, "tcp")], covered=[], already_allowed=[],
        out_of_scope=[],
    )  # fmt: skip
    new = pulumi.sg_diff(ym, t, synth).files[0].new_content
    assert (
        '        - { protocol: tcp, fromPort: 9100, toPort: 9100, cidrBlocks: ["10.0.0.0/16"], '
        "description: node exporter }\n"
        '        - { protocol: tcp, fromPort: 9100, toPort: 9100, cidrBlocks: ["10.0.9.9/32"], '
        "description: node exporter }\n"
    ) in new

    web = _target(ym, "web-sg")
    one = Synthesis([Rule("0.0.0.0/0", 443, 443, "tcp")], [], [Rule("10.0.1.0/24", 443, 443, "tcp")],
                    [], [], [])  # fmt: skip
    assert "      cidrIpv4: 10.0.1.0/24\n" in pulumi.sg_diff(ym, web, one).files[0].new_content


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


def test_s3_fix_adds_missing_flags(ym: Path) -> None:
    record, _ = run_fix_full(str(S3), ym, load_config(ym)[0], _ctx(FIX / "s3/public_unused.json"))
    assert record.diff is not None, record.stages
    udiff = record.diff.files[0].unified_diff
    assert "-      blockPublicAcls: false # reviewed 2025-03\n" in udiff
    assert "+      blockPublicAcls: true # reviewed 2025-03\n" in udiff
    assert "+      blockPublicPolicy: true\n+      restrictPublicBuckets: true\n" in udiff


def test_iam_flow_and_single_actions(ym: Path) -> None:
    spec = ym / "Pulumi.yaml"
    _edit(spec, 'Action:\n                - "ec2:*"\n                - "logs:*"\n',
          "Action: [ 'ec2:*', 'logs:*' ]\n")  # fmt: skip
    record, _ = run_fix_full(str(IAM), ym, load_config(ym)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    assert (
        "Action: [ 'ec2:DescribeInstances', 'ec2:DescribeVolumes', 'logs:CreateLogStream' ]\n"
        in record.diff.files[0].new_content
    )


def test_crlf_stays_crlf(ym: Path) -> None:
    spec = ym / "Pulumi.yaml"
    spec.write_bytes(spec.read_bytes().replace(b"\n", b"\r\n"))
    record, _ = run_fix_full(str(IAM), ym, load_config(ym)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    new = record.diff.files[0].new_content
    assert "\r\n" in new and "\n" not in new.replace("\r\n", "")


# --- stops


@pytest.mark.parametrize(
    ("old", "new", "says"),
    [
        ('cidrBlocks: ["0.0.0.0/0"]', 'cidrBlocks: ["${adminCidr}"]', "not a literal"),
        ("      ingress:\n", "      ingress: ${rules}\n      _old:\n", "not a literal list"),
        ("    properties:\n      description: bastion\n", "    get:\n      id: sg-0a91f3c2\n"
         "    properties:\n      description: bastion\n", "not a literal object"),
        ("securityGroupId: ${web-sg.id}", "securityGroupId: ${bastion-sg.id}",
         "points at a different group"),
        ("  web-https:\n    type: aws:vpc:SecurityGroupIngressRule\n",
         "  web-https:\n    type: ${ruleType}\n", "computed name"),
    ],
)  # fmt: skip
def test_sg_stops_unknown(ym: Path, old: str, new: str, says: str) -> None:
    _edit(ym / "Pulumi.yaml", old, new)
    record = run_fix(str(SG), ym, load_config(ym)[0], _ctx(FLOWS))
    assert says in _stop(record, "locate") and record.exit_code == 3


def test_unparseable_or_multi_document_yaml_stops(ym: Path) -> None:
    spec = ym / "Pulumi.yaml"
    spec.write_text(spec.read_text("utf-8") + "---\nmore: 1\n", "utf-8", newline="")
    record = run_fix(str(SG), ym, load_config(ym)[0], Context())
    assert "can't read Pulumi.yaml" in _stop(record, "locate") and record.exit_code == 3
    with pytest.raises(StageStop, match="2 YAML documents"):
        yaml_source.tree("a: 1\n---\nb: 2\n", "Main.yaml")


# --- validation and the gate


def test_validation_fails_an_edit_outside_the_target(ym: Path) -> None:
    config = load_config(ym)[0]
    _, proposal = run_fix_full(str(SG), ym, config, _ctx(FLOWS))
    assert proposal is not None
    t = _target(ym, "bastion-sg")
    f = proposal.diff.files[0]
    bad = f.model_copy(update={"new_content": f.new_content.replace("description: web", "x: y")})
    report = pulumi.validate_sg(
        ym, t, proposal.diff.model_copy(update={"files": [bad]}), proposal.synthesis,
        proposal.contract, "EC2.19", config,
    )  # fmt: skip
    assert next(c for c in report.checks if c.id == "program_scope").result is CheckResult.FAIL


def test_contract_check_source_on_yaml(ym: Path) -> None:
    config = load_config(ym)[0]
    _, proposal = run_fix_full(str(SG), ym, config, _ctx(FLOWS))
    assert proposal is not None
    cpath = ym / proposal.contract_file
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(dump_contract(proposal.contract), "utf-8")
    assert check_source(ym, config).status == "BLOCK"
    spec = ym / "Pulumi.yaml"
    spec.write_bytes(proposal.diff.files[0].new_content.encode("utf-8"))
    assert check_source(ym, config, [spec]).status == "PASS"
    _edit(spec, "\n  assets:\n", "\n  x:\n    type: aws:vpc:SecurityGroupIngressRule\n"
          "    properties: { securityGroupId: '${bastion-sg.id}', ipProtocol: '-1', "
          "cidrIpv4: 0.0.0.0/0 }\n\n  assets:\n")  # fmt: skip
    assert check_source(ym, config, [spec]).status == "UNKNOWN"
