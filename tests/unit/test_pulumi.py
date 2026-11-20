"""Pulumi support: literal reading, URN locate, source edits, static validation, contract checks."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from posturanet import pulumi
from posturanet.cli.app import app as cli
from posturanet.contracts import dump_contract
from posturanet.deliver.pr_body import safety_contract
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.gate import check_source
from posturanet.models import CheckResult
from posturanet.models.config import Config, load_config
from posturanet.pipeline import Context, run_fix, run_fix_full
from posturanet.pulumi import source
from posturanet.pulumi.stack import is_pulumi
from posturanet.synth.sg_rules import Rule
from posturanet.synth.sg_z3 import Synthesis

FIX = Path(__file__).resolve().parents[1] / "fixtures"
TS = FIX / "pulumi" / "ts-program"
PY = FIX / "pulumi" / "py-program"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
SG = FIX / "findings" / "sg_ssh_open.json"
S3 = FIX / "findings" / "s3_assets_public.json"
IAM = FIX / "findings" / "iam21_app.json"
FLOWS = FIX / "flows" / "bastion_90d.json"


@pytest.fixture
def ts(tmp_path: Path) -> Path:
    return Path(shutil.copytree(TS, tmp_path / "ts"))


@pytest.fixture
def py(tmp_path: Path) -> Path:
    return Path(shutil.copytree(PY, tmp_path / "py"))


def _ctx(evidence: Path, **kw: Any) -> Context:
    return Context(evidence=FileSource(evidence), clock=lambda: NOW, **kw)


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text("utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), "utf-8")


def _export(repo: Path, change: Any) -> None:
    path = repo / "stack-export.json"
    doc = json.loads(path.read_text("utf-8"))
    change({r["urn"].rsplit("::", 1)[-1]: r for r in doc["deployment"]["resources"]})
    path.write_text(json.dumps(doc), "utf-8")


def _stop(record: Any, stage: str) -> str:
    assert record.result == "STOPPED", record.stages
    return str(next(s for s in record.stages if s.name == stage).summary)


# --- literals


def _lit(text: str, lang: str = "ts") -> Any:
    f = Path("x.ts" if lang == "ts" else "x.py")
    call = f'new aws.s3.Thing("n", {text});\n' if lang == "ts" else f'aws.s3.Thing("n", {text})\n'
    (c,) = source.scan(f, call, "n", "Thing")
    return source.parse(c, c.args[1]).plain()


def test_literal_shapes() -> None:
    assert _lit('{ a: "x", b: 2, c: [true, -1], "d-e": { f: false } }') == {
        "a": "x", "b": 2, "c": [True, -1], "d-e": {"f": False}
    }  # fmt: skip
    assert _lit("JSON.stringify({ Version: '2012-10-17' })") == {"Version": "2012-10-17"}
    assert _lit('json.dumps({"Statement": []})', "py") == {"Statement": []}
    assert _lit('aws.ec2.SecurityGroupIngressArgs(from_port=22, cidr_blocks=["0.0.0.0/0"])', "py") == {
        "from_port": 22, "cidr_blocks": ["0.0.0.0/0"]
    }  # fmt: skip
    for computed in ("{ ...base }", "{ a }", "`x${y}`", "cfg.require('x')", "{ a: b.c }"):
        assert source.has_computed(_lit(computed)), computed
    assert source.has_computed(_lit("{name: 1}", "py"))  # a variable key in Python


def test_commented_or_unqualified_calls_are_never_matched(tmp_path: Path) -> None:
    f = tmp_path / "index.ts"
    f.write_text(
        '// new aws.ec2.SecurityGroup("sg", {});\n'
        'const s = "new aws.ec2.SecurityGroup(\\"sg\\")";\n'
        'new SecurityGroup("sg", {});\n'  # not provably the AWS class
        'new aws.ec2.SecurityGroupRule("sg", {});\n',
        "utf-8",
    )
    assert source.find([f], "sg", "SecurityGroup", "ec2") == []
    f.write_text(f.read_text("utf-8") + 'const x = new ec2.SecurityGroup("sg", {});\n', "utf-8")
    assert [c.line for c in source.find([f], "sg", "SecurityGroup", "ec2")] == [5]


# --- detection and locate


def test_detection(ts: Path, py: Path, tmp_path: Path) -> None:
    assert is_pulumi(ts, load_config(ts)[0]) and is_pulumi(py, load_config(py)[0])
    (tmp_path / "empty").mkdir()
    assert not is_pulumi(tmp_path / "empty", Config())
    (ts / "main.tf").write_text("", "utf-8")
    assert not is_pulumi(ts, Config()) and is_pulumi(ts, Config(iac="pulumi"))


def test_locate_reasoning(ts: Path) -> None:
    record = run_fix(str(SG), ts, load_config(ts)[0], Context(clock=lambda: NOW))
    assert record.result == "DRY RUN", record.stages
    loc = record.location
    assert loc is not None and loc.address == "pulumi.prod.bastion-sg"
    assert (loc.file, loc.line, loc.owners, loc.drift) == ("infra/network.ts", 4,
                                                           ["@acme/platform"], False)  # fmt: skip
    assert any("urn:pulumi:prod::acme-infra::aws:ec2/securityGroup" in r for r in loc.reasoning)
    assert not any("drift" in u for u in record.unknowns)  # checked offline from the export


def test_missing_or_unreadable_export_stops(ts: Path) -> None:
    config = load_config(ts)[0]
    config.pulumi.stack_export = None
    assert "stack export" in _stop(run_fix(str(SG), ts, config, Context()), "locate")
    (ts / "stack-export.json").write_text("{", "utf-8")
    assert "can't be read" in _stop(run_fix(str(SG), ts, load_config(ts)[0], Context()), "locate")


def test_secret_in_state_is_unknown_never_matched(ts: Path) -> None:
    def secret(r: dict[str, Any]) -> None:
        r["app"]["inputs"]["policy"] = {
            "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
            "ciphertext": "AAAA",
        }

    _export(ts, secret)
    record = run_fix(str(IAM), ts, load_config(ts)[0], _ctx(FIX / "iam/app.json"))
    assert "differs from the stack export" in _stop(record, "locate")
    assert "AAAA" not in json.dumps(record.model_dump(mode="json"))


def test_unsupported_runtime_stops_unknown(ts: Path) -> None:
    (ts / "Pulumi.yaml").write_text("name: x\nruntime: java\n", "utf-8")
    record = run_fix(str(SG), ts, load_config(ts)[0], Context())
    assert "runtime is 'java'" in _stop(record, "locate") and record.exit_code == 3


def test_scanner_and_attribute_findings_stop(ts: Path) -> None:
    record = run_fix("RDS.11:db-1", ts, load_config(ts)[0], Context())
    assert "Pulumi programs" in _stop(record, "ingest")


# --- fixes (dry run, fully offline)


def test_sg_fix_typescript(ts: Path) -> None:
    record, proposal = run_fix_full(str(SG), ts, load_config(ts)[0], _ctx(FLOWS))
    assert record.result == "DRY RUN" and proposal is not None and record.diff is not None
    udiff = record.diff.files[0].unified_diff
    assert (
        '-        { protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: ["0.0.0.0/0"]' in udiff
    )
    assert (
        '+        { protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: ["10.0.4.12/32"], '
        'description: "SSH from anywhere" },\n' in udiff
    )
    assert "node exporter" not in "".join(ln for ln in udiff.splitlines() if ln[:1] in "+-")
    assert record.diff.generator == "template:sg_ingress@1:pulumi"
    checks = {c.id: c for c in proposal.report.checks}
    assert all(c.result is CheckResult.PASS for c in checks.values() if c.required)
    preview = checks["pulumi_preview"]
    assert preview.result is CheckResult.SKIPPED and not preview.required
    assert "pulumi preview" in preview.detail
    methods = {i["id"]: i["method"] for i in safety_contract(proposal)["invariants"]}
    assert methods["drift"] == "pulumi-stack-export"


def test_sg_fix_python_standalone_rule(py: Path) -> None:
    record, _ = run_fix_full(str(SG), py, load_config(py)[0], _ctx(FLOWS))
    assert record.diff is not None, record.stages
    new = record.diff.files[0].new_content
    assert 'cidr_blocks=["10.0.4.12/32", "10.0.4.37/32", "10.0.5.9/32", "203.0.113.7/32"],' in new
    assert "0.0.0.0/0" not in new.split("web-https")[0]


def test_sg_inline_python_args_and_kept_cidrs(py: Path) -> None:
    # SSH open inline next to a private CIDR in the same entry: the private one is kept.
    main = py / "__main__.py"
    _edit(main, 'cidr_blocks=["10.0.0.0/16"]', 'cidr_blocks=["10.0.0.0/16", "0.0.0.0/0"]')
    _edit(main, "    from_port=9100,\n", "    from_port=9100,\n")

    def ingress(r: dict[str, Any]) -> None:
        for side in ("inputs", "outputs"):
            r["bastion-sg"][side]["ingress"][0]["cidrBlocks"] = ["10.0.0.0/16", "0.0.0.0/0"]

    _export(py, ingress)
    t = _target(py, "bastion-sg")
    synth = Synthesis(
        removed=[Rule("0.0.0.0/0", 9100, 9100, "tcp"), Rule("0.0.0.0/0", 22, 22, "tcp")],
        kept=[Rule("10.0.0.0/16", 9100, 9100, "tcp")],
        added=[Rule("10.0.4.12/32", 22, 22, "tcp"), Rule("10.0.9.9/32", 9100, 9100, "tcp")],
        covered=[], already_allowed=[], out_of_scope=[],
    )  # fmt: skip
    diff = pulumi.sg_diff(py, t, synth)
    new = "".join(f.new_content for f in diff.files)
    assert (
        'aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=9100, to_port=9100, '
        'cidr_blocks=["10.0.9.9/32"], description="node exporter")' in new
    )
    assert 'cidr_blocks=["10.0.4.12/32"]' in new  # the standalone SSH rule
    assert len(diff.files) == 1


def _target(repo: Path, name: str) -> pulumi.PulumiTarget:
    config = load_config(repo)[0]
    t = pulumi.resolve_address(
        repo, config, f"pulumi.prod.{name}", pulumi.load_export(repo, config, None)
    )
    assert not isinstance(t, str), t
    return t


def test_vpc_ingress_rule_holds_one_cidr(ts: Path) -> None:
    t = _target(ts, "web-sg")
    one = Synthesis([Rule("0.0.0.0/0", 443, 443, "tcp")], [], [Rule("10.0.1.0/24", 443, 443, "tcp")],
                    [], [], [])  # fmt: skip
    new = pulumi.sg_diff(ts, t, one).files[0].new_content
    assert 'cidrIpv4: "10.0.1.0/24",' in new
    two = Synthesis(one.removed, [], [*one.added, Rule("10.0.2.0/24", 443, 443, "tcp")], [], [], [])
    with pytest.raises(StageStop, match="won't add resources") as exc:
        pulumi.sg_diff(ts, t, two)
    assert exc.value.unknown


def test_sg_literals_that_dont_explain_the_export_stop(ts: Path) -> None:
    _export(ts, lambda r: r["bastion-sg"]["inputs"]["ingress"].pop())
    record = run_fix(str(SG), ts, load_config(ts)[0], _ctx(FLOWS))
    assert "1 ingress rule(s) in the stack export but 2" in _stop(record, "locate")
    assert record.exit_code == 3


def test_sg_security_group_source_stops(ts: Path) -> None:
    _edit(
        ts / "infra/network.ts", 'cidrBlocks: ["10.0.0.0/16"],', 'securityGroups: ["sg-0b22c4d6"],'
    )

    def peer(r: dict[str, Any]) -> None:
        for side in ("inputs", "outputs"):
            e = r["bastion-sg"][side]["ingress"][1]
            e["securityGroups"] = ["sg-0b22c4d6"]
            del e["cidrBlocks"]

    _export(ts, peer)
    assert "security group or prefix list" in _stop(
        run_fix(str(SG), ts, load_config(ts)[0], _ctx(FLOWS)), "locate"
    )


def test_rule_retargeted_in_code_stops(ts: Path) -> None:
    _edit(ts / "infra/network.ts", "securityGroupId: web.id,", "securityGroupId: bastionSg.id,")
    record = run_fix(str(SG), ts, load_config(ts)[0], _ctx(FLOWS))
    assert "points at a different group" in _stop(record, "locate")


def test_s3_fix_both_languages(ts: Path, py: Path) -> None:
    ev = _ctx(FIX / "s3/public_unused.json")
    record, _ = run_fix_full(str(S3), ts, load_config(ts)[0], ev)
    assert record.diff is not None, record.stages
    udiff = record.diff.files[0].unified_diff
    assert "-    blockPublicAcls: false,\n+    blockPublicAcls: true,\n" in udiff
    assert "+    blockPublicPolicy: true,\n+    restrictPublicBuckets: true,\n" in udiff
    record, _ = run_fix_full(str(S3), py, load_config(py)[0], ev)
    assert record.diff is not None, record.stages
    assert "+    ignore_public_acls=True,\n+    restrict_public_buckets=True,\n" in (
        record.diff.files[0].unified_diff
    )


def test_s3_already_blocked_stops(ts: Path) -> None:
    store = ts / "infra/storage.ts"
    _edit(store, "blockPublicAcls: false,", "blockPublicAcls: true, blockPublicPolicy: true, "
          "restrictPublicBuckets: true,")  # fmt: skip
    flags = dict.fromkeys(
        ("blockPublicAcls", "blockPublicPolicy", "ignorePublicAcls", "restrictPublicBuckets"), True
    )
    _export(ts, lambda r: [r["assets-pab"][s].update(flags) for s in ("inputs", "outputs")])
    record = run_fix(str(S3), ts, load_config(ts)[0], _ctx(FIX / "s3/public_unused.json"))
    assert "already sets every flag" in _stop(record, "fix")


def test_iam_fix_keeps_layout(ts: Path, py: Path) -> None:
    record, _ = run_fix_full(str(IAM), ts, load_config(ts)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    assert (
        '            Action: [\n                "ec2:DescribeInstances",\n'
        '                "ec2:DescribeVolumes",\n                "logs:CreateLogStream",\n'
        "            ],\n" in record.diff.files[0].new_content
    )
    record, _ = run_fix_full(str(IAM), py, load_config(py)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    assert '"Action": ["ec2:DescribeInstances", "ec2:DescribeVolumes", "logs:CreateLogStream"]' in (
        record.diff.files[0].new_content
    )


def test_iam_single_string_action(ts: Path) -> None:
    store = ts / "infra/storage.ts"
    _edit(store, '"ec2:*",\n                "logs:*",\n', '"ec2:*",\n')
    _edit(store, 'Action: [\n                "ec2:*",\n            ],', 'Action: "ec2:*",')

    def one(r: dict[str, Any]) -> None:
        for side in ("inputs", "outputs"):
            doc = json.loads(r["app"][side]["policy"])
            doc["Statement"][0]["Action"] = "ec2:*"
            r["app"][side]["policy"] = json.dumps(doc)

    _export(ts, one)
    record, _ = run_fix_full(str(IAM), ts, load_config(ts)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    assert 'Action: ["ec2:DescribeInstances", "ec2:DescribeVolumes"],' in (
        record.diff.files[0].new_content
    )


def test_crlf_source_stays_crlf(ts: Path) -> None:
    path = ts / "infra/storage.ts"
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    record, _ = run_fix_full(str(IAM), ts, load_config(ts)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    new = record.diff.files[0].new_content
    assert "\r\n" in new and "\n" not in new.replace("\r\n", "")


# --- validation catches a bad edit


def test_validation_fails_an_edit_outside_the_target(ts: Path) -> None:
    config = load_config(ts)[0]
    _, proposal = run_fix_full(str(SG), ts, config, _ctx(FLOWS))
    assert proposal is not None
    t = _target(ts, "bastion-sg")
    f = proposal.diff.files[0]
    bad = f.model_copy(update={"new_content": f.new_content.replace('"web"', '"web2"')})
    diff = proposal.diff.model_copy(update={"files": [bad]})
    report = pulumi.validate_sg(
        ts, t, diff, proposal.synthesis, proposal.contract, "EC2.19", config
    )
    scope = next(c for c in report.checks if c.id == "program_scope")
    assert scope.result is CheckResult.FAIL

    still_open = f.model_copy(update={"new_content": t.original})
    report = pulumi.validate_sg(
        ts, t, proposal.diff.model_copy(update={"files": [still_open]}), proposal.synthesis,
        proposal.contract, "EC2.19", config,
    )  # fmt: skip
    failed = {c.id for c in report.checks if c.result is CheckResult.FAIL}
    assert {"source", "template_matches", "recheck"} <= failed


def test_check_mode_needs_no_aws(ts: Path) -> None:
    record = run_fix(str(SG), ts, load_config(ts)[0], _ctx(FLOWS, mode="check"))
    assert record.result == "VALIDATED", record.stages
    assert not (ts / "posturanet" / "contracts").exists() or any(
        (ts / "posturanet" / "contracts").iterdir()
    )


# --- contract check --source


def test_contract_check_source_on_pulumi(ts: Path) -> None:
    config = load_config(ts)[0]
    _, proposal = run_fix_full(str(SG), ts, config, _ctx(FLOWS))
    assert proposal is not None
    cpath = ts / proposal.contract_file
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(dump_contract(proposal.contract), "utf-8")

    open_now = check_source(ts, config)
    assert open_now.status == "BLOCK"
    assert (open_now.results[0].source_file, open_now.results[0].source_line) == (
        "infra/network.ts", 4,
    )  # fmt: skip

    net = ts / "infra/network.ts"
    net.write_bytes(proposal.diff.files[0].new_content.encode("utf-8"))
    assert check_source(ts, config, [net]).status == "PASS"
    assert check_source(ts, config, [ts / "infra/storage.ts"]).results == []

    # a rule written since the last deploy could reopen the group: UNKNOWN, never PASS
    _edit(net, "\nexport const", '\nnew aws.vpc.SecurityGroupIngressRule("x", { securityGroupId: '
          'bastionSg.id, ipProtocol: "-1", cidrIpv4: "0.0.0.0/0" });\nexport const')  # fmt: skip
    assert check_source(ts, config, [net]).status == "UNKNOWN"

    config.pulumi.stack_export = "missing.json"
    unknown = check_source(ts, config)
    assert unknown.status == "UNKNOWN" and "stack export" in unknown.results[0].reasons[0]


def test_cli_dry_run_smoke(ts: Path) -> None:
    result = CliRunner().invoke(
        cli,
        ["fix", str(SG), "--dry-run", "--repo", str(ts), "--evidence-file", str(FLOWS), "--ascii"],
    )
    assert result.exit_code == 0, result.output
    assert "infra/network.ts:4 -> pulumi.prod.bastion-sg" in result.output
    assert "pulumi_preview" in result.output or "pulumi preview" in result.output
    assert not (ts / "posturanet").exists()  # dry run writes no contract
