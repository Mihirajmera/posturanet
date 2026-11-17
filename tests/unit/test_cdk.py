"""AWS CDK support: construct locate, source edits, synth validation and contract checks."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from posturanet import cdk
from posturanet.aws.readonly import ReadOnlyClient, iam_action, is_allowed
from posturanet.cdk import source
from posturanet.cdk.app import SubprocessCdk
from posturanet.cli.app import app as cli
from posturanet.contracts import dump_contract
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.gate import check_source
from posturanet.models.config import Config, load_config
from posturanet.pipeline import Context, run_fix, run_fix_full

FIX = Path(__file__).resolve().parents[1] / "fixtures"
TS = FIX / "cdk" / "ts-app"
PY = FIX / "cdk" / "py-app"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
SG = FIX / "findings" / "sg_ssh_open.json"
S3 = FIX / "findings" / "s3_assets_public.json"
IAM = FIX / "findings" / "iam21_app.json"
FLOWS = FIX / "flows" / "bastion_90d.json"


def _copy(src: Path, tmp: Path) -> Path:
    dst = tmp / src.name
    shutil.copytree(src, dst)
    return dst


@pytest.fixture
def ts(tmp_path: Path) -> Path:
    return _copy(TS, tmp_path)


@pytest.fixture
def py(tmp_path: Path) -> Path:
    return _copy(PY, tmp_path)


def _ctx(evidence: Path, **kw: Any) -> Context:
    return Context(evidence=FileSource(evidence), clock=lambda: NOW, **kw)


Transform = Callable[[dict[str, Any]], None]


class FakeCdk:
    """`cdk synth` stand-in: copies the fixture assembly, then applies `transform` to a stack
    template, as CDK would after the source edit. Records what the source said during synth."""

    def __init__(
        self, repo: Path, template: str, transform: Transform | None, fail: str | None = None
    ) -> None:
        self.repo, self.template, self.transform, self.fail = repo, template, transform, fail
        self.seen: dict[str, str] = {}

    def synth(self, app: Path, out: Path) -> str | None:
        for f in source.source_files(app):
            self.seen[f.relative_to(app).as_posix()] = f.read_text("utf-8")
        shutil.copytree(self.repo / "cdk.out", out, dirs_exist_ok=True)
        if self.transform is not None:
            path = out / self.template
            doc = json.loads(path.read_text("utf-8"))
            self.transform(doc["Resources"])
            path.write_text(json.dumps(doc), "utf-8")
        return self.fail


def _fake_aws(repo: Path, template: str, ingress: list[dict[str, Any]] | None = None) -> Any:
    """Read-only clients: the deployed template is the fixture assembly's."""
    body = (repo / "cdk.out" / template).read_text("utf-8")

    class Fake:
        def get_template(self, **kw: Any) -> dict[str, Any]:
            return {"TemplateBody": json.loads(body)}

        def describe_stack_resources(self, **kw: Any) -> dict[str, Any]:
            return json.loads((repo / "stack-resources.json").read_text("utf-8"))

        def describe_security_groups(self, **kw: Any) -> dict[str, Any]:
            perms = ingress or [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 9100, "ToPort": 9100,
                 "IpRanges": [{"CidrIp": "10.0.0.0/16"}]},
            ]  # fmt: skip
            return {"SecurityGroups": [{"GroupId": "sg-0a91f3c2", "IpPermissions": perms}]}

    return lambda service: ReadOnlyClient(Fake(), service)


# --- source scanning


def test_mask_hides_comments_and_strings() -> None:
    text = "a('x(') // b(\nc /* d( */ `e(${f}` g\n"
    masked = source.mask(text, "ts")
    assert len(masked) == len(text) and masked.count("\n") == 2
    assert "(" not in masked.replace("a(", "")
    py = source.mask('x = "(" # (\ny = """\n(\n"""\n', "py")
    assert "(" not in py and py.count("\n") == 4


def test_commented_out_construct_is_never_matched(tmp_path: Path) -> None:
    f = tmp_path / "s.ts"
    text = (
        "// new ec2.SecurityGroup(this, 'Sg', {});\n"
        "const s = 'new ec2.SecurityGroup(this, \"Sg\")';\n"
        "new ec2.CfnSecurityGroup(this, 'Sg', {});\n"
    )
    assert source.scan(f, text, "Sg", "SecurityGroup") == []
    hits = source.scan(f, text + "const sg = new ec2.SecurityGroup(this, 'Sg', { vpc });\n", "Sg",
                       "SecurityGroup")  # fmt: skip
    assert [(h.line, h.var, h.qualifier) for h in hits] == [(4, "sg", "ec2.")]


@pytest.mark.parametrize(
    ("expr", "rule"),
    [
        ("ec2.Port.tcp(22)", (22, 22, "tcp")),
        ("Port.udpRange(1000, 2000)", (1000, 2000, "udp")),
        ("ec2.Port.all_tcp()", (0, 65535, "tcp")),
        ("ec2.Port.allTraffic()", (-1, -1, "-1")),
        ("ec2.Port.HTTPS", (443, 443, "tcp")),
    ],
)
def test_port_literals(expr: str, rule: tuple[int, int, str]) -> None:
    got = source._port(expr)
    assert got is not None and got[1:] == rule


def test_computed_peer_stops_unknown(tmp_path: Path) -> None:
    f = tmp_path / "s.ts"
    text = (
        "const sg = new ec2.SecurityGroup(this, 'Sg', { vpc });\n"
        "sg.addIngressRule(ec2.Peer.ipv4(props.cidr), ec2.Port.tcp(22));\n"
    )
    (c,) = source.scan(f, text, "Sg", "SecurityGroup")
    with pytest.raises(StageStop) as exc:
        source.ingress_calls(c)
    assert exc.value.unknown and "won't guess" in exc.value.reason


def test_variable_assigned_twice_stops(tmp_path: Path) -> None:
    f = tmp_path / "s.py"
    text = 'sg = ec2.SecurityGroup(self, "Sg", vpc=vpc)\nsg = other\n'
    (c,) = source.scan(f, text, "Sg", "SecurityGroup")
    with pytest.raises(StageStop, match="assigned more than once"):
        source.ingress_calls(c)


def test_s3_props_layouts(tmp_path: Path) -> None:
    f = tmp_path / "s.ts"
    cases = {
        "new s3.Bucket(this, 'B');": "new s3.Bucket(this, 'B', { blockPublicAccess: "
        "s3.BlockPublicAccess.BLOCK_ALL });",
        "new s3.Bucket(this, 'B', {});": "new s3.Bucket(this, 'B', { blockPublicAccess: "
        "s3.BlockPublicAccess.BLOCK_ALL });",
        "new s3.Bucket(this, 'B', { versioned: true });": "new s3.Bucket(this, 'B', { versioned: "
        "true, blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL });",
        "new s3.Bucket(this, 'B', { blockPublicAccess: s3.BlockPublicAccess.BLOCK_ACLS });": "new "
        "s3.Bucket(this, 'B', { blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL });",
        "new s3.Bucket(this, 'B', {\n  blockPublicAccess: new s3.BlockPublicAccess({\n"
        "    blockPublicAcls: false,\n  }),\n});": "new s3.Bucket(this, 'B', {\n"
        "  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,\n});",
    }
    for before, after in cases.items():
        (c,) = source.scan(f, before, "B", "Bucket")
        new, _ = source.render_s3(c)
        assert new == after
        assert source.blocks_all(source.rescan(c, new))


def test_s3_python_kwargs_and_stops(tmp_path: Path) -> None:
    f = tmp_path / "s.py"
    (c,) = source.scan(f, 's3.Bucket(self, "B", versioned=True)', "B", "Bucket")
    assert source.render_s3(c)[0] == (
        's3.Bucket(self, "B", versioned=True, block_public_access=s3.BlockPublicAccess.BLOCK_ALL)'
    )
    for text, match in [
        ('s3.Bucket(self, "B", public_read_access=True)', "public_read_access"),
        ('s3.Bucket(self, "B", **props)', "spread"),
        ('s3.Bucket(self, "B", block_public_access=bpa)', "block_public_access"),
        ('s3.Bucket(self, "B", block_public_access=s3.BlockPublicAccess.BLOCK_ALL)', "drifted"),
    ]:
        (c,) = source.scan(f, text, "B", "Bucket")
        with pytest.raises(StageStop, match=match):
            source.render_s3(c)


def test_unqualified_bucket_needs_import(tmp_path: Path) -> None:
    f = tmp_path / "s.ts"
    (c,) = source.scan(f, "new Bucket(this, 'B', {});", "B", "Bucket")
    with pytest.raises(StageStop, match="import"):
        source.render_s3(c)
    text = "import { BlockPublicAccess, Bucket } from 'aws-cdk-lib/aws-s3';\nnew Bucket(this, 'B');"
    (c,) = source.scan(f, text, "B", "Bucket")
    assert "{ blockPublicAccess: BlockPublicAccess.BLOCK_ALL }" in source.render_s3(c)[0]


# --- detection and locate


def test_detection(ts: Path, py: Path) -> None:
    assert cdk.is_cdk(ts, load_config(ts)[0])
    assert cdk.is_cdk(py, load_config(py)[0])
    assert not cdk.is_cdk(FIX / "cfn" / "basic", load_config(FIX / "cfn" / "basic")[0])
    assert not cdk.is_cdk(FIX / "tf" / "basic", Config())


def test_locate_maps_construct_path_to_source_line(ts: Path) -> None:
    from posturanet.ingest import ingest

    config, _ = load_config(ts)
    loc, target = cdk.locate(ingest(str(SG)), ts, config, None, None, ["AWS::EC2::SecurityGroup"],
                             None, dry=True)  # fmt: skip
    assert (loc.address, loc.file, loc.line) == (
        "cdk.network.BastionSg1A2B3C4D",
        "lib/network-stack.ts",
        15,
    )
    assert loc.owners == ["@acme/platform"]
    assert target.construct_path == "network/BastionSg/Resource"
    assert any("aws:cdk:path" in r for r in loc.reasoning)


def test_locate_nested_stage_python(py: Path) -> None:
    record = run_fix(str(SG), py, load_config(py)[0])
    assert record.result == "DRY RUN", record.stages
    assert record.location is not None
    assert (record.location.file, record.location.line) == ("stacks/platform.py", 17)
    assert record.location.address == "cdk.Prod-platform.BastionSg1A2B3C4D"


def _locate_stop(repo: Path) -> StageStop:
    record = run_fix(str(SG), repo, load_config(repo)[0])
    assert record.result == "STOPPED" and record.exit_code == 3, record.stages
    locate = next(s for s in record.stages if s.name == "locate")
    assert locate.status.value == "unknown", locate
    return StageStop("locate", locate.summary)


def test_locate_duplicate_id_is_unknown(ts: Path) -> None:
    extra = ts / "lib" / "other-stack.ts"
    extra.write_text("const s = new ec2.SecurityGroup(this, 'BastionSg', { vpc });\n", "utf-8")
    assert "can't tell which" in _locate_stop(ts).reason


def test_locate_computed_id_is_unknown(ts: Path) -> None:
    path = ts / "lib" / "network-stack.ts"
    path.write_text(path.read_text("utf-8").replace("'BastionSg'", "`${id}Sg`"), "utf-8")
    assert "may be computed" in _locate_stop(ts).reason


def test_unreadable_source_is_unknown_at_locate(ts: Path) -> None:
    extra = ts / "lib" / "broken.ts"
    extra.write_text("const x = new ec2.SecurityGroup(this, 'BastionSg', { vpc ;\n", "utf-8")
    assert "can't read the app source" in _locate_stop(ts).reason


def test_locate_without_path_metadata_or_l1_is_unknown(ts: Path) -> None:
    tpl = ts / "cdk.out" / "network.template.json"
    doc = json.loads(tpl.read_text("utf-8"))
    doc["Resources"]["BastionSg1A2B3C4D"]["Metadata"]["aws:cdk:path"] = "network/BastionSg"
    tpl.write_text(json.dumps(doc), "utf-8")
    assert "not an L2" in _locate_stop(ts).reason
    del doc["Resources"]["BastionSg1A2B3C4D"]["Metadata"]
    tpl.write_text(json.dumps(doc), "utf-8")
    assert "no aws:cdk:path" in _locate_stop(ts).reason


def test_dry_run_without_assembly_stops(ts: Path) -> None:
    config, _ = load_config(ts)
    config.cdk.assembly = None
    record = run_fix(str(SG), ts, config)
    assert record.result == "STOPPED"
    assert any("doesn't run cdk synth" in s.summary for s in record.stages)
    assert any("cdk.assembly" in n for n in record.next_steps)


# --- fixes (dry run)


def test_sg_fix_typescript(ts: Path) -> None:
    record, proposal = run_fix_full(str(SG), ts, load_config(ts)[0], _ctx(FLOWS))
    assert record.result == "DRY RUN", record.stages
    assert proposal is not None and record.diff is not None
    udiff = record.diff.files[0].unified_diff
    assert "-    bastionSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), " in udiff
    assert (
        "+    bastionSg.addIngressRule(ec2.Peer.ipv4('10.0.4.12/32'), ec2.Port.tcp(22), "
        "'SSH from anywhere');\n" in udiff
    )
    assert "node exporter" not in "".join(ln for ln in udiff.splitlines() if ln[:1] in "+-")
    assert record.diff.generator == "template:sg_ingress@1:cdk"
    checks = {c.id: c.result.value for c in proposal.report.checks}
    assert checks["source"] == "pass" and checks["cdk_synth"] == "skipped"
    from posturanet.deliver.pr_body import safety_contract

    methods = {i["id"]: i["method"] for i in safety_contract(proposal)["invariants"]}
    assert methods["drift"] == "cloudformation-gettemplate"
    assert methods["cdk_synth"] == "cdk-synth"


def test_sg_fix_python(py: Path) -> None:
    record, _ = run_fix_full(str(SG), py, load_config(py)[0], _ctx(FLOWS))
    assert record.diff is not None, record.stages
    new = record.diff.files[0].new_content
    assert 'bastion_sg.add_ingress_rule(ec2.Peer.ipv4("10.0.5.9/32"), ec2.Port.tcp(22), ' in new
    assert "any_ipv4" not in new


def test_sg_rules_outside_the_source_stop_unknown(ts: Path) -> None:
    tpl = ts / "cdk.out" / "network.template.json"
    doc = json.loads(tpl.read_text("utf-8"))
    doc["Resources"]["BastionSg1A2B3C4D"]["Properties"]["SecurityGroupIngress"].append(
        {"CidrIp": "192.168.0.0/16", "FromPort": 5432, "ToPort": 5432, "IpProtocol": "tcp"}
    )  # e.g. from bastionSg.connections.allowFrom(...) elsewhere
    tpl.write_text(json.dumps(doc), "utf-8")
    record = run_fix(str(SG), ts, load_config(ts)[0], _ctx(FLOWS))
    assert record.result == "STOPPED" and record.exit_code == 3
    fix = next(s for s in record.stages if s.name == "fix")
    assert fix.status.value == "unknown" and "3 ingress rule(s) in the template" in fix.summary


def test_sg_peer_from_standalone_ingress_stops_unknown(ts: Path) -> None:
    # e.g. webSg.connections.allowFrom(bastionSg, ...) synthesizes a standalone ingress
    tpl = ts / "cdk.out" / "network.template.json"
    doc = json.loads(tpl.read_text("utf-8"))
    doc["Resources"]["BastionSgfromWebSg5432"] = {
        "Type": "AWS::EC2::SecurityGroupIngress",
        "Properties": {
            "GroupId": {"Fn::GetAtt": ["BastionSg1A2B3C4D", "GroupId"]},
            "SourceSecurityGroupId": {"Fn::GetAtt": ["WebSgE5F6A7B8", "GroupId"]},
            "FromPort": 5432,
            "ToPort": 5432,
            "IpProtocol": "tcp",
        },
    }
    tpl.write_text(json.dumps(doc), "utf-8")
    record = run_fix(str(SG), ts, load_config(ts)[0], _ctx(FLOWS))
    assert record.result == "STOPPED" and record.exit_code == 3, record.stages
    assert record.diff is None
    assert any(s.status.value == "unknown" for s in record.stages)


def test_s3_fix_both_languages(ts: Path, py: Path) -> None:
    ev = _ctx(FIX / "s3/public_unused.json")
    record, _ = run_fix_full(str(S3), ts, load_config(ts)[0], ev)
    assert record.diff is not None, record.stages
    assert "+      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,\n" in (
        record.diff.files[0].unified_diff
    )
    record, _ = run_fix_full(str(S3), py, load_config(py)[0], ev)
    assert record.diff is not None, record.stages
    assert "+            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,\n" in (
        record.diff.files[0].unified_diff
    )


def test_iam_fix_keeps_layout(ts: Path, py: Path) -> None:
    record, _ = run_fix_full(str(IAM), ts, load_config(ts)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    new = record.diff.files[0].new_content.replace("\r\n", "\n")
    assert (
        "          actions: [\n            'ec2:DescribeInstances',\n"
        "            'ec2:DescribeVolumes',\n            'logs:CreateLogStream',\n          ],\n"
        in new
    )
    record, _ = run_fix_full(str(IAM), py, load_config(py)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None, record.stages
    assert (
        'actions=["ec2:DescribeInstances", "ec2:DescribeVolumes", "logs:CreateLogStream"]'
        in record.diff.files[0].new_content
    )


def test_iam_statements_added_elsewhere_stop_unknown(ts: Path) -> None:
    tpl = ts / "cdk.out" / "iam.template.json"
    doc = json.loads(tpl.read_text("utf-8"))
    stmts = doc["Resources"]["AppPolicy5A6B7C8D"]["Properties"]["PolicyDocument"]["Statement"]
    stmts.append({"Action": "ec2:DescribeInstances", "Effect": "Allow", "Resource": "*"})
    tpl.write_text(json.dumps(doc), "utf-8")
    record = run_fix(str(IAM), ts, load_config(ts)[0], _ctx(FIX / "iam/app.json"))
    assert record.result == "STOPPED"
    fix = next(s for s in record.stages if s.name == "fix")
    assert fix.status.value == "unknown" and "one-for-one" in fix.summary


def test_crlf_source_stays_crlf(ts: Path) -> None:
    path = ts / "lib" / "iam-stack.ts"
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    record, _ = run_fix_full(str(IAM), ts, load_config(ts)[0], _ctx(FIX / "iam/app.json"))
    assert record.diff is not None
    new = record.diff.files[0].new_content
    assert "\r\n" in new and "\n" not in new.replace("\r\n", "")


# --- validation through cdk synth (check mode)


def _bastion_fixed(rules: list[tuple[str, int]]) -> Transform:
    def t(res: dict[str, Any]) -> None:
        res["BastionSg1A2B3C4D"]["Properties"]["SecurityGroupIngress"] = [
            {"CidrIp": c, "FromPort": p, "ToPort": p, "IpProtocol": "tcp"} for c, p in rules
        ]

    return t


FIXED = [("10.0.4.12/32", 22), ("10.0.4.37/32", 22), ("10.0.5.9/32", 22), ("203.0.113.7/32", 22),
         ("10.0.0.0/16", 9100)]  # fmt: skip


def _check(repo: Path, runner: FakeCdk) -> Any:
    config, _ = load_config(repo)
    config.cdk.assembly = None  # locate synthesizes too
    aws = _fake_aws(repo, "network.template.json")
    return run_fix(str(SG), repo, config, _ctx(FLOWS, mode="check", aws=aws, cdk=runner))


def test_check_mode_validates_through_synth(ts: Path) -> None:
    original = (ts / "lib/network-stack.ts").read_bytes()
    runner = FakeCdk(ts, "network.template.json", None)
    fixing = FakeCdk(ts, "network.template.json", _bastion_fixed(FIXED))

    class Both:
        n = 0

        def synth(self, app: Path, out: Path) -> str | None:
            Both.n += 1
            return (runner if Both.n == 1 else fixing).synth(app, out)

    record = _check(ts, Both())  # type: ignore[arg-type]
    assert record.result == "VALIDATED", record.stages
    assert Both.n == 2
    # the edit was on disk during the second synth, and put back afterwards
    assert "Peer.ipv4('10.0.4.12/32')" in fixing.seen["lib/network-stack.ts"]
    assert "anyIpv4" in runner.seen["lib/network-stack.ts"]
    assert (ts / "lib/network-stack.ts").read_bytes() == original
    checks = {c.id: c.result.value for c in record.validation.checks}  # type: ignore[union-attr]
    assert checks == {
        "guardrails": "pass",
        "source": "pass",
        "cdk_synth": "pass",
        "template_scope": "pass",
        "template_matches": "pass",
        "invariants": "pass",
        "recheck": "pass",
        "drift": "pass",
        "cdk_diff": "skipped",
        "changeset": "skipped",
    }


def _stops_validation(repo: Path, fixing: FakeCdk, first: FakeCdk) -> str:
    class Both:
        n = 0

        def synth(self, app: Path, out: Path) -> str | None:
            Both.n += 1
            return (first if Both.n == 1 else fixing).synth(app, out)

    record = _check(repo, Both())  # type: ignore[arg-type]
    assert record.result == "STOPPED" and record.exit_code == 4, record.stages
    return next(s for s in record.stages if s.name == "validate").summary


def test_synthesized_template_still_open_fails(ts: Path) -> None:
    first = FakeCdk(ts, "network.template.json", None)
    summary = _stops_validation(ts, FakeCdk(ts, "network.template.json", None), first)
    assert "template_scope FAIL" in summary  # nothing changed in the template


def test_synth_touching_other_resources_fails(ts: Path) -> None:
    def also_web(res: dict[str, Any]) -> None:
        _bastion_fixed(FIXED)(res)
        res["WebSgE5F6A7B8"]["Properties"]["GroupDescription"] = "changed"

    first = FakeCdk(ts, "network.template.json", None)
    summary = _stops_validation(ts, FakeCdk(ts, "network.template.json", also_web), first)
    assert "more than the target resource" in summary


def test_synth_failure_fails(ts: Path) -> None:
    first = FakeCdk(ts, "network.template.json", None)
    broken = FakeCdk(ts, "network.template.json", None, fail="exit 1: TS2304")
    assert "doesn't synthesize: exit 1: TS2304" in _stops_validation(ts, broken, first)
    assert "anyIpv4" in (ts / "lib/network-stack.ts").read_text("utf-8")


@pytest.mark.parametrize("lang", ["ts", "py"])
def test_check_mode_s3_and_iam(lang: str, ts: Path, py: Path) -> None:
    repo = ts if lang == "ts" else py
    tpl = {"ts": ("storage.template.json", "iam.template.json")}.get(
        lang, ("assembly-Prod/Prodplatform1F2E3D4C.template.json",) * 2
    )

    def blocked(res: dict[str, Any]) -> None:
        res["Assets1C2D3E4F"]["Properties"]["PublicAccessBlockConfiguration"] = {
            k: True
            for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls",
                      "RestrictPublicBuckets")
        }  # fmt: skip

    def shrunk(res: dict[str, Any]) -> None:
        st = res["AppPolicy5A6B7C8D"]["Properties"]["PolicyDocument"]["Statement"][0]
        st["Action"] = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "logs:CreateLogStream"]

    for finding, ev, template, transform in [
        (S3, "s3/public_unused.json", tpl[0], blocked),
        (IAM, "iam/app.json", tpl[1], shrunk),
    ]:
        runner = FakeCdk(repo, template, transform)
        aws = _fake_aws(repo, template)
        ctx = _ctx(FIX / ev, mode="check", aws=aws, cdk=runner)
        record = run_fix(str(finding), repo, load_config(repo)[0], ctx)
        assert record.result == "VALIDATED", record.stages
        assert record.validation is not None
        checks = {c.id: c.result.value for c in record.validation.checks}
        assert checks["cdk_synth"] == checks["recheck"] == checks["template_scope"] == "pass"


def test_check_mode_uses_only_allowlisted_aws_calls(ts: Path) -> None:
    calls: list[str] = []
    fake = _fake_aws(ts, "network.template.json")

    def factory(service: str) -> ReadOnlyClient:
        inner = fake(service)

        class Spy:
            def __getattr__(self, name: str) -> Any:
                calls.append(iam_action(service, name))
                return getattr(inner, name)

        return ReadOnlyClient(Spy(), service)

    config, _ = load_config(ts)
    config.cloudformation.stack_resources = None
    runner = FakeCdk(ts, "network.template.json", _bastion_fixed(FIXED))
    ctx = _ctx(FLOWS, mode="check", aws=factory, cdk=runner)
    run_fix(str(SG), ts, config, ctx)
    assert calls and all(is_allowed(c) for c in calls), calls


def test_subprocess_cdk_runs_without_aws_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    class Proc:
        returncode = 0
        stdout = stderr = ""

    def fake_run(args: list[str], **kw: Any) -> Proc:
        seen["args"], seen["env"], seen["cwd"] = args, kw["env"], kw["cwd"]
        return Proc()

    monkeypatch.setattr("posturanet.cdk.app.shutil.which", lambda b: f"/bin/{b}")
    monkeypatch.setattr("posturanet.cdk.app.subprocess.run", fake_run)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.setenv("AWS_PROFILE", "prod")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    assert SubprocessCdk().synth(tmp_path, tmp_path / "out") is None
    assert seen["args"][1:4] == ["synth", "--no-lookups", "--no-notices"]
    env = seen["env"]
    assert "AWS_ACCESS_KEY_ID" not in env and "AWS_PROFILE" not in env
    assert env["AWS_REGION"] == "us-east-1" and env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert "no-aws-config" in env["AWS_SHARED_CREDENTIALS_FILE"]
    monkeypatch.setattr("posturanet.cdk.app.shutil.which", lambda b: None)
    assert SubprocessCdk().synth(tmp_path, tmp_path) == "cdk not found on PATH"


# --- contract check --source


def test_contract_check_source_on_cdk(ts: Path) -> None:
    config, _ = load_config(ts)
    _, proposal = run_fix_full(str(SG), ts, config, _ctx(FLOWS))
    assert proposal is not None
    cpath = ts / proposal.contract_file
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(dump_contract(proposal.contract), "utf-8")

    open_now = check_source(ts, config)
    assert open_now.status == "BLOCK"
    assert open_now.results[0].source_file == "lib/network-stack.ts"
    assert open_now.results[0].source_line == 15

    tpl = ts / "cdk.out" / "network.template.json"
    doc = json.loads(tpl.read_text("utf-8"))
    _bastion_fixed(FIXED)(doc["Resources"])
    tpl.write_text(json.dumps(doc), "utf-8")
    src = ts / "lib" / "network-stack.ts"
    assert check_source(ts, config, [src]).status == "PASS"
    assert check_source(ts, config, [ts / "lib" / "iam-stack.ts"]).results == []

    config.cdk.assembly = "missing"
    unknown = check_source(ts, config)
    assert unknown.status == "UNKNOWN" and "manifest.json" in unknown.results[0].reasons[0]


# --- offline smoke test through the CLI


def test_cli_dry_run_smoke(ts: Path) -> None:
    result = CliRunner().invoke(
        cli,
        ["fix", str(SG), "--dry-run", "--repo", str(ts), "--evidence-file", str(FLOWS), "--ascii"],
    )
    assert result.exit_code == 0, result.output
    assert "lib/network-stack.ts:15 -> cdk.network.BastionSg1A2B3C4D" in result.output
    assert "DRY RUN" in result.output
    assert "Peer.ipv4('10.0.4.12/32')" in result.output
    assert not (ts / "posturanet").exists()  # dry run writes no contract
