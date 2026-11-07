"""Checkov and Trivy findings: Terraform addresses resolved against the state (FR-4b)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from posturanet.cli.app import app
from posturanet.errors import StageStop
from posturanet.ingest import iac, ingest, read_findings
from posturanet.ingest.controls import fix_type_for
from posturanet.locate import resolve_address
from posturanet.models import FixType
from posturanet.models.config import load_config

FIX = Path(__file__).resolve().parents[1] / "fixtures"
CHECKOV = FIX / "findings" / "checkov_scan.json"
TRIVY = FIX / "findings" / "trivy_scan.json"
SHA = "0" * 64
runner = CliRunner()


def _split(tmp_path: Path, scan: Path) -> dict[str, Path]:
    out = tmp_path / "split"
    result = runner.invoke(app, ["findings", "split", str(scan), "--out", str(out)])
    assert result.exit_code == 0, result.output
    return {p.name.split("-", 1)[0]: p for p in out.iterdir()}


# --- reading reports


def test_checkov_report_lists_terraform_failures_only() -> None:
    found = read_findings(CHECKOV)
    assert found.format == "checkov"
    assert len(found.entries) == 4  # the secrets report is not Terraform
    assert [e.control_id for e in found.fixable] == ["EC2.13", "RDS.8", "DynamoDB.2"]
    unsupported = found.entries[1]
    assert unsupported.finding is not None
    assert (unsupported.finding.control_id, unsupported.finding.fix_type) == (
        "CKV_AWS_23",
        FixType.UNSUPPORTED,
    )


def test_checkov_finding_keeps_the_address() -> None:
    f = read_findings(CHECKOV).entries[0].finding
    assert f is not None
    assert f.source == "checkov"
    assert f.resource.address == "aws_security_group.this"
    assert f.resource.type == "aws_security_group"
    assert f.provenance.schema_name == "checkov-json"


def test_trivy_report_lists_failures() -> None:
    found = read_findings(TRIVY)
    assert found.format == "trivy"
    assert [e.control_id for e in found.fixable] == ["RDS.8", "DynamoDB.2", "EC2.19"]
    sg = found.fixable[2].finding
    assert sg is not None
    assert sg.resource.address == "module.bastion.aws_security_group.this"
    assert sg.finding_id.startswith("trivy:AWS-0107:")  # AVD- prefix dropped
    assert "PASS" in (found.entries[4].reason or "")


@pytest.mark.parametrize(
    ("raw", "address"),
    [
        ("aws_db_instance.orders", "aws_db_instance.orders"),
        ("module.a.module.b[0].aws_s3_bucket.x", "module.a.module.b[0].aws_s3_bucket.x"),
        ('aws_instance.web["blue"]', 'aws_instance.web["blue"]'),
        ("aws_instance.web[2] (extra)", "aws_instance.web[2]"),
        ("google_storage_bucket.x", ""),
        ("", ""),
    ],
)
def test_address_parsing(raw: str, address: str) -> None:
    assert iac._address(raw) == address


def test_missing_address_stops() -> None:
    with pytest.raises(StageStop, match="resource address"):
        iac.parse_checkov_item({"check_id": "CKV_AWS_293", "resource": "?"}, raw_sha256=SHA)


def test_passed_checkov_check_stops() -> None:
    item = {
        "check_id": "CKV_AWS_293",
        "resource": "aws_db_instance.orders",
        "check_result": {"result": "PASSED"},
    }
    with pytest.raises(StageStop, match="nothing to fix"):
        iac.parse_checkov_item(item, raw_sha256=SHA)


def test_several_controls_narrow_by_resource_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(iac, "check_map", lambda tool: {"X": ["RDS.7", "RDS.8"]})
    assert iac.control_for("checkov", "X", "aws_db_instance") == "RDS.8"
    assert iac.control_for("checkov", "X", "aws_rds_cluster") == "RDS.7"
    with pytest.raises(StageStop, match="several controls"):
        iac.control_for("checkov", "X", "aws_s3_bucket")


@pytest.mark.parametrize("tool", ["checkov", "trivy"])
def test_every_mapped_control_is_one_posturanet_fixes(tool: iac.Tool) -> None:
    for check, controls in iac.check_map(tool).items():
        for control in controls:
            assert fix_type_for(control) is not FixType.UNSUPPORTED, (tool, check, control)


# --- resolving addresses against the state


def test_module_resource_found_without_its_module_path(basic_repo: Path) -> None:
    f = iac.parse_checkov_item(
        {"check_id": "CKV_AWS_24", "resource": "aws_security_group.this"}, raw_sha256=SHA
    )
    resolved = resolve_address(f, basic_repo, load_config(basic_repo)[0])
    assert resolved.resource.id == "sg-0a91f3c2"
    assert resolved.resource.arn == (
        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a91f3c2"
    )
    assert resolved.resource.address == "module.bastion.aws_security_group.this"


def test_resource_not_applied_yet_stops(basic_repo: Path) -> None:
    f = iac.parse_checkov_item(
        {"check_id": "CKV_AWS_24", "resource": "aws_security_group.new"}, raw_sha256=SHA
    )
    with pytest.raises(StageStop, match="not in the Terraform state"):
        resolve_address(f, basic_repo, load_config(basic_repo)[0])


def _state_with(tmp_path: Path, basic_repo: Path, extra: list[dict[str, Any]]) -> Path:
    state = json.loads((basic_repo / "state.fixture.json").read_text("utf-8"))
    state["resources"] += extra
    path = tmp_path / "state.json"
    path.write_text(json.dumps(state), encoding="utf-8")
    return path


def test_same_name_in_two_modules_stops(tmp_path: Path, basic_repo: Path) -> None:
    state = json.loads((basic_repo / "state.fixture.json").read_text("utf-8"))
    twin = copy.deepcopy(state["resources"][0])
    twin["module"] = "module.other"
    twin["instances"][0]["attributes"]["id"] = "sg-0bbbbbbb"
    path = _state_with(tmp_path, basic_repo, [twin])
    f = iac.parse_checkov_item(
        {"check_id": "CKV_AWS_24", "resource": "aws_security_group.this"}, raw_sha256=SHA
    )
    with pytest.raises(StageStop, match="matches 2 state entries"):
        resolve_address(f, basic_repo, load_config(basic_repo)[0], state_path=path)


def test_rule_resource_resolves_to_its_group(tmp_path: Path, basic_repo: Path) -> None:
    rule = {
        "mode": "managed",
        "type": "aws_security_group_rule",
        "name": "ssh",
        "instances": [{"attributes": {"id": "sgrule-1", "security_group_id": "sg-0a91f3c2"}}],
    }
    path = _state_with(tmp_path, basic_repo, [rule])
    f = iac.parse_checkov_item(
        {"check_id": "CKV_AWS_24", "resource": "aws_security_group_rule.ssh"}, raw_sha256=SHA
    )
    resolved = resolve_address(f, basic_repo, load_config(basic_repo)[0], state_path=path)
    assert (resolved.resource.id, resolved.resource.arn) == ("sg-0a91f3c2", None)


# --- end to end (dry run)


def test_checkov_security_group_gets_the_same_fix(
    tmp_path: Path, basic_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    split = _split(tmp_path, CHECKOV)
    args = ["--dry-run", "--repo", str(basic_repo), "--evidence-file", str(flows_path)]
    ours = runner.invoke(app, ["fix", str(split["EC2.13"]), *args])
    hub = runner.invoke(app, ["fix", str(sg_finding_path), *args])
    assert ours.exit_code == hub.exit_code == 0, ours.output
    assert "checkov EC2.13 · sg-0a91f3c2" in ours.output
    diff = ours.output[ours.output.index("Proposed change") : ours.output.index("Result")]
    assert diff and diff in hub.output


def test_trivy_rds_finding_gets_a_settings_fix(tmp_path: Path) -> None:
    split = _split(tmp_path, TRIVY)
    repo = FIX / "tf" / "config"
    out = runner.invoke(app, ["fix", str(split["RDS.8"]), "--dry-run", "--repo", str(repo)])
    assert out.exit_code == 0, out.output
    assert "trivy RDS.8" in out.output
    assert "+  deletion_protection = true" in out.output


def test_scan_with_several_fixable_findings_needs_a_choice() -> None:
    from posturanet.errors import UsageError

    with pytest.raises(UsageError, match="findings split"):
        ingest(str(TRIVY))
