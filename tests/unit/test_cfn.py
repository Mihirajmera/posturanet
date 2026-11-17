"""CloudFormation and SAM support: locate, edit, validate, contract check (FR-5, FR-20, FR-21)."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from test_readonly import Recorder

from posturanet import cfn
from posturanet.aws.readonly import ReadOnlyClient, is_allowed
from posturanet.cfn.template import TemplateError, parse, value
from posturanet.contracts import dump_contract
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.gate import check_source
from posturanet.ingest import ingest
from posturanet.models.config import Config, load_config
from posturanet.pipeline import Context, run_fix, run_fix_full

FIX = Path(__file__).resolve().parents[1] / "fixtures"
CFN = FIX / "cfn" / "basic"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
SG = FIX / "findings" / "sg_ssh_open.json"
S3 = FIX / "findings" / "s3_assets_public.json"
IAM = FIX / "findings" / "iam21_app.json"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    dst = tmp_path / "repo"
    shutil.copytree(CFN, dst)
    return dst


def _fake_aws(body: str) -> Any:
    """A read-only CloudFormation client whose deployed template is `body`."""

    class Cfn:
        def get_template(self, **kw: Any) -> dict[str, Any]:
            return {"TemplateBody": body}

    return lambda service: ReadOnlyClient(Cfn(), service)


def _ctx(evidence: Path, **kw: Any) -> Context:
    return Context(evidence=FileSource(evidence), clock=lambda: NOW, **kw)


def _res(repo: Path, stack: str, logical: str) -> cfn.CfnResource:
    config, _ = load_config(repo)
    res = cfn.resolve(repo, config, stack, logical)
    assert isinstance(res, cfn.CfnResource), res
    return res


# --- template


def test_short_form_intrinsics_read_as_long_form(tmp_path: Path) -> None:
    text = (
        "Resources:\n  A:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      BucketName: !Sub '${AWS::StackName}-x'\n"
        "      Tags: [{Key: a, Value: !GetAtt B.Arn}, {Key: r, Value: !Ref P}]\n"
        "      N: !Join [',', [a, b]]\n"
    )
    props = value(parse(text, tmp_path / "t.yaml").resources["A"])["Properties"]
    assert props["BucketName"] == {"Fn::Sub": "${AWS::StackName}-x"}
    assert props["Tags"][0]["Value"] == {"Fn::GetAtt": ["B", "Arn"]}
    assert props["Tags"][1]["Value"] == {"Ref": "P"}
    assert props["N"] == {"Fn::Join": [",", ["a", "b"]]}


def test_not_a_template(tmp_path: Path) -> None:
    with pytest.raises(TemplateError):
        parse("foo: bar\n", tmp_path / "x.yaml")


def test_detection(repo: Path, tmp_path: Path) -> None:
    config, _ = load_config(repo)
    assert cfn.is_cloudformation(repo, config)
    assert not cfn.is_cloudformation(FIX / "tf" / "basic", Config())
    bare = tmp_path / "bare"
    shutil.copytree(CFN / "templates", bare)
    assert cfn.is_cloudformation(bare, Config())  # templates and no .tf


# --- locate


def test_locate_maps_physical_id_to_template_line(repo: Path) -> None:
    config, _ = load_config(repo)
    loc, res = cfn.locate(ingest(str(SG)), repo, config, None, None, [cfn.SG_TYPE])
    assert (loc.address, loc.file, loc.line) == (
        "cfn.network.BastionSG",
        "templates/network.yaml",
        10,
    )
    assert loc.owners == ["@acme/platform"]
    assert res.logical_id == "BastionSG"


def test_locate_sam_generated_resource_is_unknown(repo: Path) -> None:
    config, _ = load_config(repo)
    res = cfn.resolve(repo, config, "storage", "ThumbnailFunctionRole", "AWS::IAM::Role")
    assert isinstance(res, str) and "SAM transform" in res


def test_locate_ambiguous_template_needs_mapping(repo: Path) -> None:
    shutil.copy(repo / "templates" / "network.yaml", repo / "templates" / "network-dev.yaml")
    config, _ = load_config(repo)
    res = cfn.resolve(repo, config, "network", "BastionSG", cfn.SG_TYPE)
    assert isinstance(res, str) and "cloudformation.templates.network" in res
    config.cloudformation.templates["network"] = "templates/network.yaml"
    assert isinstance(cfn.resolve(repo, config, "network", "BastionSG"), cfn.CfnResource)


def test_locate_not_in_any_stack_stops_unknown(repo: Path) -> None:
    config, _ = load_config(repo)
    finding = ingest("sg-0ffffffff")
    with pytest.raises(StageStop) as exc:
        cfn.locate(finding, repo, config, None, None, [cfn.SG_TYPE])
    assert exc.value.unknown


def test_live_locate_and_drift_use_only_allowlisted_calls(repo: Path) -> None:
    calls: list[str] = []

    class Cfn(Recorder):
        def __getattr__(self, name: str) -> Any:
            op = super().__getattr__(name)

            def wrapped(**kw: Any) -> Any:
                op(**kw)
                if name == "describe_stack_resources":
                    return json.loads((repo / "stack-resources.json").read_text("utf-8"))
                return {"TemplateBody": (repo / "templates/network.yaml").read_text("utf-8")}

            return wrapped

    def factory(service: str) -> ReadOnlyClient:
        return ReadOnlyClient(Cfn(service, calls), service)

    config, _ = load_config(repo)
    config.cloudformation.stack_resources = None
    finding = ingest(str(SG))
    _, res = cfn.locate(finding, repo, config, None, factory, [cfn.SG_TYPE])
    from posturanet.cfn.validate import _drift

    assert _drift(res, factory, offline=False).result.value == "pass"
    assert calls == ["cloudformation:DescribeStackResources", "cloudformation:GetTemplate"]
    assert all(is_allowed(c) for c in calls)
    assert not is_allowed("cloudformation:CreateChangeSet")
    assert not is_allowed("cloudformation:ExecuteChangeSet")


# --- edit


def test_sg_edit_keeps_comments_and_untouched_entries(repo: Path) -> None:
    record, proposal = run_fix_full(
        str(SG), repo, load_config(repo)[0], _ctx(FIX / "flows/bastion_90d.json")
    )
    assert record.result == "DRY RUN", record.stages
    assert proposal is not None
    new = proposal.diff.files[0].new_content.replace("\r\n", "\n")
    assert "0.0.0.0/0\n          Description: SSH" not in new
    assert "# Bastion host access" in new and "# monitoring stays as it is" in new
    assert "CidrIp: 10.0.4.12/32\n          Description: SSH from anywhere" in new
    assert "{IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0}" in new  # WebSG
    removed = [ln for ln in proposal.diff.files[0].unified_diff.splitlines() if ln.startswith("-")]
    assert removed[1:] == ["-          CidrIp: 0.0.0.0/0"]
    checks = {c.id: c.result.value for c in proposal.report.checks}
    assert checks["template_scope"] == checks["invariants"] == checks["recheck"] == "pass"
    assert checks["template_matches"] == "pass"
    assert checks["changeset"] == "skipped" and checks["drift"] == "skipped"


def test_sg_flow_edit(repo: Path) -> None:
    res = _res(repo, "network", "WebSG")
    sg = cfn.parse_sg(res)
    from posturanet.cfn.edit import render_sg
    from posturanet.synth.sg_rules import Rule
    from posturanet.synth.sg_z3 import Synthesis

    added = [Rule("192.0.2.0/24", 443, 443, "tcp")]
    synth = Synthesis(sg.rules(), [], added, [], [], [])
    new = render_sg(sg, synth)
    assert (
        "- {IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 192.0.2.0/24, "
        "Description: Observed sources kept by PosturaNet}\n" in new
    )
    edited = parse(new, res.template.path)
    assert value(edited.resources["BastionSG"]) == value(res.template.resources["BastionSG"])


def test_s3_edit_inserts_block_into_sam_template(repo: Path) -> None:
    res = _res(repo, "storage", "AssetsBucket")
    diff, already = cfn.s3_diff(repo, res)
    assert already == []
    new = diff.files[0].new_content.replace("\r\n", "\n")
    assert (
        "    Status: Enabled\n      PublicAccessBlockConfiguration:\n        BlockPublicAcls: true\n"
        in new
    )
    assert all(v is True for v in cfn.s3_flags(_edited(res, new)).values())


def test_s3_edit_flips_false_flags_and_adds_missing(repo: Path) -> None:
    path = repo / "templates/storage.yaml"
    text = path.read_text("utf-8").replace(
        "      VersioningConfiguration:",
        "      PublicAccessBlockConfiguration:\n        BlockPublicAcls: false\n"
        "        IgnorePublicAcls: true\n      VersioningConfiguration:",
    )
    path.write_bytes(text.encode("utf-8"))
    res = _res(repo, "storage", "AssetsBucket")
    diff, already = cfn.s3_diff(repo, res)
    assert already == ["IgnorePublicAcls"]
    new = diff.files[0].new_content.replace("\r\n", "\n")
    assert (
        "BlockPublicAcls: true\n        IgnorePublicAcls: true\n        BlockPublicPolicy: true\n"
        in new
    )
    assert all(v is True for v in cfn.s3_flags(_edited(res, new)).values())


def test_s3_intrinsic_flag_stops(repo: Path) -> None:
    path = repo / "templates/storage.yaml"
    text = path.read_text("utf-8").replace(
        "      VersioningConfiguration:",
        "      PublicAccessBlockConfiguration:\n        BlockPublicAcls: !Ref Block\n"
        "      VersioningConfiguration:",
    )
    path.write_bytes(text.encode("utf-8"))
    with pytest.raises(StageStop):
        cfn.s3_diff(repo, _res(repo, "storage", "AssetsBucket"))


def test_iam_json_edit_keeps_layout(repo: Path) -> None:
    record, _ = run_fix_full(str(IAM), repo, load_config(repo)[0], _ctx(FIX / "iam/app.json"))
    assert record.result == "DRY RUN", record.stages
    assert record.diff is not None
    udiff = record.diff.files[0].unified_diff
    assert '+                "ec2:DescribeInstances",\n' in udiff
    assert '-                "ec2:*",\n' in udiff
    new = record.diff.files[0].new_content
    assert json.loads(new)["Resources"]["AppPolicy"]["Properties"]["PolicyDocument"]["Statement"][
        0
    ]["Action"] == ["ec2:DescribeInstances", "ec2:DescribeVolumes", "logs:CreateLogStream"]


def test_iam_yaml_scalar_action_becomes_block_list(tmp_path: Path) -> None:
    text = (
        "Resources:\n  P:\n    Type: AWS::IAM::ManagedPolicy\n    Properties:\n"
        "      PolicyDocument:\n        Statement:\n          - Effect: Allow\n"
        '            Action: "*"\n            Resource: "*"\n'
    )
    t = parse(text, tmp_path / "p.yaml")
    res = cfn.CfnResource("s", "P", cfn.POLICY_TYPE, t, t.resources["P"], 2)
    from posturanet.cfn.edit import iam_edit

    new = iam_edit(cfn.parse_policy(res), {0: ["s3:GetObject", "s3:ListBucket", "sqs:A", "sqs:B"]})
    assert "            Action:\n              - s3:GetObject\n" in new
    edited = value(parse(new, t.path).resources["P"])
    assert edited["Properties"]["PolicyDocument"]["Statement"][0]["Action"][3] == "sqs:B"


# --- pipeline


def test_s3_account_control_stops_unknown(repo: Path) -> None:
    record = run_fix(str(FIX / "findings/s3_account_bpa.json"), repo, load_config(repo)[0])
    assert record.result == "STOPPED" and record.exit_code == 3


def test_check_mode_validates_with_deployed_template(repo: Path) -> None:
    """Without --dry-run the drift check reads the deployed template; matching → VALIDATED."""

    body = (repo / "templates/network.yaml").read_text("utf-8")
    ctx = _ctx(FIX / "flows/bastion_90d.json", mode="check", aws=_fake_aws(body))
    config, _ = load_config(repo)
    config.evidence.min_confidence_for_pr = "medium"
    record = run_fix(str(SG), repo, config, ctx)
    assert record.result == "VALIDATED", record.stages
    assert (repo / "posturanet/contracts/cfn.network.BastionSG.yaml").is_file()

    drifted = body.replace("FromPort: 9100", "FromPort: 9101")
    ctx = _ctx(FIX / "flows/bastion_90d.json", mode="check", aws=_fake_aws(drifted))
    record = run_fix(str(SG), repo, config, ctx)
    assert record.result == "STOPPED" and record.exit_code == 4
    assert any("differs from stack network" in s.summary for s in record.stages)


# --- contract check --source


def test_contract_check_source_on_templates(repo: Path) -> None:
    config, _ = load_config(repo)
    _, proposal = run_fix_full(str(SG), repo, config, _ctx(FIX / "flows/bastion_90d.json"))
    assert proposal is not None
    cpath = repo / proposal.contract_file
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(dump_contract(proposal.contract), "utf-8")

    open_now = check_source(repo, config)
    assert open_now.status == "BLOCK"  # the open rule breaks must_deny
    target = repo / "templates/network.yaml"
    target.write_text(proposal.diff.files[0].new_content, "utf-8")
    assert check_source(repo, config, [target]).status == "PASS"

    broken = proposal.diff.files[0].new_content.replace("10.0.4.12/32", "10.0.9.0/32")
    target.write_text(broken, "utf-8")
    result = check_source(repo, config, [target])
    assert result.status == "BLOCK"
    assert result.results[0].source_file == "templates/network.yaml"
    assert check_source(repo, config, [repo / "templates/iam.json"]).results == []


def test_contract_check_source_s3_template(repo: Path) -> None:
    config, _ = load_config(repo)
    body = (repo / "templates/storage.yaml").read_text("utf-8")
    ctx = _ctx(FIX / "s3/public_unused.json", mode="check", aws=_fake_aws(body))
    record = run_fix(str(S3), repo, config, ctx)
    assert record.result == "VALIDATED", record.stages
    assert (repo / "posturanet/contracts/cfn.storage.AssetsBucket.yaml").is_file()
    assert check_source(repo, config).status != "PASS"  # no Block Public Access yet
    assert record.diff is not None
    (repo / "templates/storage.yaml").write_text(record.diff.files[0].new_content, "utf-8")
    assert check_source(repo, config).status == "PASS"


def _edited(res: cfn.CfnResource, new: str) -> cfn.CfnResource:
    t = parse(new, res.template.path)
    return cfn.CfnResource(res.stack, res.logical_id, res.type, t, t.resources[res.logical_id], 1)


# --- contract build --all, verify, hook and MCP


def test_contract_build_all_lists_template_resources(repo: Path) -> None:
    from typer.testing import CliRunner

    from posturanet.cli.app import app

    args = ["contract", "build", "--all", "--dry-run", "--repo", str(repo), "--format", "json"]
    result = CliRunner().invoke(app, args)
    rows = json.loads(result.output[result.output.index("[") :])
    # ThumbnailFunctionRole is an IAM::Role the SAM transform generates: not listed
    assert [r["group"] for r in rows] == [
        "sg-0a91f3c2",
        "sg-0b22c4d6",
        "acme-assets",
        "arn:aws:iam::123456789012:policy/app",
    ]
    assert all(r["result"] for r in rows), rows


def test_contract_build_all_needs_the_export(repo: Path) -> None:
    config, _ = load_config(repo)
    config.cloudformation.stack_resources = None
    from posturanet.errors import UsageError

    with pytest.raises(UsageError):
        cfn.template_rows(repo, config, None, [cfn.SG_TYPE])


class _PR:
    def __init__(self, body: str) -> None:
        self.body = body

    def get_pr(self, number: int) -> dict[str, Any]:
        return {"body": self.body, "merged_at": "2026-10-31T00:00:00Z", "state": "closed"}


def _merged_sg(repo: Path) -> tuple[_PR, str]:
    from posturanet.deliver.idempotency import verify_marker
    from posturanet.deliver.pr_body import verify_spec

    config, _ = load_config(repo)
    _, proposal = run_fix_full(str(SG), repo, config, _ctx(FIX / "flows/bastion_90d.json"))
    assert proposal is not None
    spec = verify_spec(proposal)  # type: ignore[arg-type]
    assert spec.address == "cfn.network.BastionSG"
    return _PR(verify_marker(spec)), proposal.diff.files[0].new_content


def test_verify_cfn_fix_from_the_deployed_template(repo: Path, tmp_path: Path) -> None:
    from posturanet.verify import VerifyContext, run_verify

    pr, fixed = _merged_sg(repo)
    config, _ = load_config(repo)
    deployed = tmp_path / "get-template.json"
    deployed.write_text(json.dumps({"TemplateBody": fixed}), "utf-8")  # get-template output
    ctx = VerifyContext(github=pr, state_path=deployed, watch_hours=0)  # type: ignore[arg-type]
    record = run_verify("acme/infra#7", repo, config, ctx)
    assert record.result == "CONFIRMED", record.stages
    assert "the template in get-template.json shows the fix" in record.stages[1].summary

    deployed.write_text((repo / "templates/network.yaml").read_text("utf-8"), "utf-8")
    record = run_verify("acme/infra#7", repo, config, ctx)
    assert record.result == "NOT APPLIED" and record.exit_code == 3

    calls: list[str] = []

    class Cfn(Recorder):
        def get_template(self, **kw: Any) -> dict[str, Any]:
            super().__getattr__("get_template")(**kw)
            return {"TemplateBody": fixed}

    def aws(service: str) -> ReadOnlyClient:
        return ReadOnlyClient(Cfn(service, calls), service)

    ctx = VerifyContext(github=pr, aws=aws, watch_hours=0)  # type: ignore[arg-type]
    from unittest.mock import patch

    with patch("posturanet.verify._hub_note", return_value=None):
        record = run_verify("acme/infra#7", repo, config, ctx)
    assert record.result == "CONFIRMED", record.stages
    assert calls == ["cloudformation:GetTemplate"]


def test_verify_cfn_without_a_template_source_stops_unknown(repo: Path) -> None:
    from posturanet.verify import VerifyContext, run_verify

    pr, _ = _merged_sg(repo)
    ctx = VerifyContext(github=pr, watch_hours=0)  # type: ignore[arg-type]
    record = run_verify("acme/infra#7", repo, load_config(repo)[0], ctx)
    assert record.result == "STOPPED" and record.exit_code == 3
    assert "cloudformation:GetTemplate" in " ".join(record.next_steps)


def _contracted(repo: Path) -> str:
    """Write the BastionSG contract; return the fixed template text."""
    _, proposal = run_fix_full(
        str(SG), repo, load_config(repo)[0], _ctx(FIX / "flows/bastion_90d.json")
    )
    assert proposal is not None
    cpath = repo / proposal.contract_file
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(dump_contract(proposal.contract), "utf-8")
    return proposal.diff.files[0].new_content


def _event(path: Path) -> str:
    return json.dumps({"tool_name": "Edit", "tool_input": {"file_path": str(path)}})


def test_hook_checks_template_edits(repo: Path) -> None:
    from posturanet.hooks import claude_code

    fixed = _contracted(repo)
    target = repo / "templates/network.yaml"
    target.write_text(fixed, "utf-8")
    assert claude_code(_event(target), repo) == ""

    target.write_text(fixed.replace("10.0.4.12/32", "10.0.9.0/32"), "utf-8")
    assert json.loads(claude_code(_event(target), repo))["decision"] == "block"

    target.write_text(fixed + "\n  : [unclosed\n", "utf-8")  # no longer parses: never a PASS
    out = json.loads(claude_code(_event(target), repo))
    assert "not valid YAML" in out["hookSpecificOutput"]["additionalContext"]

    other = repo / "config.yaml"  # YAML that isn't a template passes through untouched
    other.write_text("Resources: [not, cfn\n", "utf-8")
    assert claude_code(_event(other), repo) == ""


def test_mcp_check_change_on_template_files(repo: Path) -> None:
    from posturanet.mcp.server import check_change

    fixed = _contracted(repo)
    assert check_change(repo=str(repo), files=["templates/network.yaml"])["status"] == "BLOCK"
    (repo / "templates/network.yaml").write_text(fixed, "utf-8")
    assert check_change(repo=str(repo), files=["templates/network.yaml"])["status"] == "PASS"
    (repo / "notes.json").write_text('{"a": 1}', "utf-8")
    result = check_change(repo=str(repo), files=["notes.json"])
    assert result["status"] == "PASS" and result["results"] == []
