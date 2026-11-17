"""Checkov and Trivy findings on CloudFormation/SAM templates flow into the CFN pipeline."""

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
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.ingest import ingest, read_findings
from posturanet.ingest.iac import split_template_ref, template_ref
from posturanet.models import FixType
from posturanet.models.config import Config, load_config
from posturanet.pipeline import Context, run_fix, run_fix_full

FIX = Path(__file__).resolve().parents[1] / "fixtures"
CFN = FIX / "cfn" / "basic"
CHECKOV = FIX / "cfn" / "scanners" / "checkov_cfn.json"
TRIVY = FIX / "cfn" / "scanners" / "trivy_cfn.json"
NOW = datetime(2026, 10, 30, tzinfo=UTC)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    dst = tmp_path / "repo"
    shutil.copytree(CFN, dst)
    return dst


def _config(repo: Path) -> Config:
    config, _ = load_config(repo)
    config.cloudformation.templates = {
        "network": "templates/network.yaml",
        "storage": "./templates/storage.yaml",
    }
    return config


# --- ingest


def test_template_ref_normalizes_scanner_paths() -> None:
    assert template_ref("/templates/a.yaml", "Web") == "cfn-template:templates/a.yaml#Web"
    assert template_ref(".\\templates\\a.yaml", "Web") == "cfn-template:templates/a.yaml#Web"
    assert template_ref("a.yaml", "Not.Logical") == ""
    assert split_template_ref("cfn-template:t/a.yaml#Web") == ("t/a.yaml", "Web")
    assert split_template_ref("aws_security_group.x") is None


def test_checkov_cloudformation_report() -> None:
    found = read_findings(CHECKOV)
    assert found.format == "checkov" and len(found.entries) == 2
    [entry] = found.fixable
    f = entry.finding
    assert f is not None
    assert (f.control_id, f.fix_type) == ("S3.8", FixType.S3_PUBLIC)
    assert f.resource.type == "AWS::S3::Bucket"
    assert f.resource.address == "cfn-template:templates/storage.yaml#AssetsBucket"
    # Attribute fixes edit Terraform only: CKV_AWS_21 stays unsupported on a template.
    other = found.entries[1].finding
    assert other is not None and other.fix_type is FixType.UNSUPPORTED


def test_trivy_cloudformation_report() -> None:
    f = ingest(str(TRIVY))
    assert (f.control_id, f.fix_type) == ("EC2.19", FixType.SG_INGRESS)
    assert f.resource.address == "cfn-template:templates/network.yaml#BastionSG"


# --- locate


def test_resolve_template_ref_maps_to_stack_and_physical_id(repo: Path) -> None:
    f = cfn.resolve_template_ref(ingest(str(CHECKOV)), repo, _config(repo), None, None)
    assert (f.resource.id, f.resource.address) == ("acme-assets", "cfn.storage.AssetsBucket")
    assert f.resource.type == "AWS::S3::Bucket"
    f = cfn.resolve_template_ref(ingest(str(TRIVY)), repo, _config(repo), None, None)
    assert (f.resource.id, f.resource.type) == ("sg-0a91f3c2", cfn.SG_TYPE)


def test_unmapped_template_stops_unknown(repo: Path) -> None:
    config, _ = load_config(repo)  # no cloudformation.templates
    with pytest.raises(StageStop) as exc:
        cfn.resolve_template_ref(ingest(str(TRIVY)), repo, config, None, None)
    assert exc.value.unknown and "no stack is mapped" in exc.value.reason

    config.cloudformation.templates = {"a": "templates/network.yaml", "b": "templates/network.yaml"}
    with pytest.raises(StageStop) as exc:
        cfn.resolve_template_ref(ingest(str(TRIVY)), repo, config, None, None)
    assert exc.value.unknown and "2 stacks" in exc.value.reason


def test_wrong_type_or_undeployed_stops_unknown(repo: Path) -> None:
    f = ingest(str(CHECKOV))
    wrong = f.model_copy(update={"resource": f.resource.model_copy(update={"type": cfn.SG_TYPE})})
    with pytest.raises(StageStop) as exc:
        cfn.resolve_template_ref(wrong, repo, _config(repo), None, None)
    assert exc.value.unknown

    export = repo / "stack-resources.json"
    rows = json.loads(export.read_text("utf-8"))
    rows["StackResources"] = [r for r in rows["StackResources"] if r["StackName"] != "storage"]
    export.write_text(json.dumps(rows), "utf-8")
    with pytest.raises(StageStop) as exc:
        cfn.resolve_template_ref(f, repo, _config(repo), None, None)
    assert exc.value.unknown and "0 deployed resources" in exc.value.reason


def test_without_export_reads_the_stack_with_allowlisted_call(repo: Path) -> None:
    calls: list[str] = []
    kwargs: list[dict[str, Any]] = []

    class Cfn(Recorder):
        def __getattr__(self, name: str) -> Any:
            op = super().__getattr__(name)

            def wrapped(**kw: Any) -> Any:
                op(**kw)
                kwargs.append(kw)
                return json.loads((repo / "stack-resources.json").read_text("utf-8"))

            return wrapped

    def factory(service: str) -> ReadOnlyClient:
        return ReadOnlyClient(Cfn(service, calls), service)

    config = _config(repo)
    config.cloudformation.stack_resources = None
    f = cfn.resolve_template_ref(ingest(str(TRIVY)), repo, config, None, factory)
    assert f.resource.id == "sg-0a91f3c2"
    assert calls == ["cloudformation:DescribeStackResources"] and all(map(is_allowed, calls))
    assert kwargs == [{"StackName": "network", "LogicalResourceId": "BastionSG"}]

    with pytest.raises(StageStop, match="needs AWS access"):
        cfn.resolve_template_ref(ingest(str(TRIVY)), repo, config, None, None)


# --- pipeline


def test_trivy_template_finding_runs_the_sg_fix(repo: Path) -> None:
    ctx = Context(evidence=FileSource(FIX / "flows/bastion_90d.json"), clock=lambda: NOW)
    record, proposal = run_fix_full(str(TRIVY), repo, _config(repo), ctx)
    assert record.result == "DRY RUN", record.stages
    assert record.finding is not None and record.finding.resource.id == "sg-0a91f3c2"
    assert proposal is not None
    assert record.location is not None and record.location.address == "cfn.network.BastionSG"
    removed = [ln for ln in proposal.diff.files[0].unified_diff.splitlines() if ln.startswith("-")]
    assert removed[1:] == ["-          CidrIp: 0.0.0.0/0"]


def test_template_finding_routes_to_cfn_in_terraform_mode(repo: Path) -> None:
    config = _config(repo)
    config.iac = "terraform"
    config.cloudformation.templates = {}
    record = run_fix(str(TRIVY), repo, config)
    assert record.result == "STOPPED" and record.exit_code == 3
    assert "no stack is mapped" in (record.why or "")
