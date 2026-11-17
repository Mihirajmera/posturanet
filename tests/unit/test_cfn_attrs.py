"""Attribute fixes (configfix catalog rows) on CloudFormation and SAM templates."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from posturanet import cfn
from posturanet.aws.readonly import ReadOnlyClient
from posturanet.cfn.edit import attr_edit, attr_unmet
from posturanet.cfn.template import parse, value
from posturanet.configfix import catalog, fixes_for
from posturanet.configfix.catalog import ConfigFix
from posturanet.errors import StageStop
from posturanet.models import CheckResult
from posturanet.models.config import Config, load_config
from posturanet.pipeline import Context, run_fix

FIX = Path(__file__).resolve().parents[1] / "fixtures"
RDS8 = FIX / "findings" / "rds_deletion_protection.json"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    dst = tmp_path / "repo"
    shutil.copytree(FIX / "cfn" / "attrs", dst)
    return dst


def _row(control: str, cfn_type: str | None = None) -> ConfigFix:
    rows = [r for r in (f.for_cfn() for f in fixes_for(control)) if r is not None]
    return next(r for r in rows if cfn_type is None or r.resource_type == cfn_type)


def _res(tmp_path: Path, text: str, logical: str = "R", name: str = "t.yaml") -> cfn.CfnResource:
    (tmp_path / name).write_text(text, "utf-8")
    res = cfn.resolve(tmp_path, Config(), "s", logical)
    assert isinstance(res, cfn.CfnResource), res
    return res


def _props(new: str, logical: str = "R") -> Any:
    return value(parse(new, Path("t.yaml")).resources[logical])["Properties"]


# --- catalog


def test_cfn_mapping_is_complete_or_absent() -> None:
    mapped = [f for f in catalog() if f.cfn_type]
    assert len(mapped) > 40
    for f in mapped:
        row = f.for_cfn()
        assert row is not None, f.control
        assert row.resource_type.startswith("AWS::")
        assert all(c.path[0].isupper() for c in row.changes), f.control
    # No CloudFormation property for these: they stop with UNKNOWN on templates.
    for control in ("ELB.4", "EC2.8", "EKS.8", "S3.17", "CloudTrail.1", "IAM.7"):
        assert all(f.for_cfn() is None for f in fixes_for(control)), control


def test_merged_rows_keep_the_cfn_type() -> None:
    (row,) = [r for r in fixes_for("RDS.2+RDS.8") if r.resource_type == "aws_db_instance"]
    cfn_row = row.for_cfn()
    assert cfn_row is not None and cfn_row.resource_type == "AWS::RDS::DBInstance"
    assert {c.path for c in cfn_row.changes} == {"PubliclyAccessible", "DeletionProtection"}


# --- edits


def test_flips_quoted_false_and_keeps_comment(tmp_path: Path) -> None:
    text = (
        "Resources:\n  R:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      Engine: postgres\n"
        '      DeletionProtection: "false" # keep me\n'
    )
    new, changed, already = attr_edit(_res(tmp_path, text), _row("RDS.8"))
    assert new == text.replace('"false"', "true")
    assert changed == ["DeletionProtection = true"] and already == []


def test_inserts_nested_block_yaml(tmp_path: Path) -> None:
    text = (
        "Resources:\n  R:\n    Type: AWS::DynamoDB::Table\n    Properties:\n"
        "      TableName: events\n"
        "  Other:\n    Type: AWS::SNS::Topic\n"
    )
    new, _, _ = attr_edit(_res(tmp_path, text), _row("DynamoDB.2"))
    assert new == text.replace(
        "      TableName: events\n",
        "      TableName: events\n"
        "      PointInTimeRecoverySpecification:\n"
        "        PointInTimeRecoveryEnabled: true\n",
    )


def test_adds_properties_when_absent(tmp_path: Path) -> None:
    text = "Resources:\n  R:\n    Type: AWS::DynamoDB::Table\n"
    new, _, _ = attr_edit(_res(tmp_path, text), _row("DynamoDB.6"))
    assert _props(new) == {"DeletionProtectionEnabled": True}


def test_json_two_changes_share_one_new_parent(tmp_path: Path) -> None:
    text = json.dumps(
        {"Resources": {"R": {"Type": "AWS::Kinesis::Stream", "Properties": {"ShardCount": 1}}}},
        indent=2,
    )
    new, changed, _ = attr_edit(_res(tmp_path, text, name="t.json"), _row("Kinesis.1"))
    doc = json.loads(new)  # still JSON
    assert doc["Resources"]["R"]["Properties"]["StreamEncryption"] == {
        "EncryptionType": "KMS",
        "KeyId": "alias/aws/kinesis",
    }
    assert len(changed) == 2
    assert new.startswith('{\n  "Resources": {\n    "R": {')


def test_flow_yaml_mapping(tmp_path: Path) -> None:
    text = (
        "Resources:\n  R:\n    Type: AWS::ECR::Repository\n    Properties: {RepositoryName: app}\n"
    )
    new, _, _ = attr_edit(_res(tmp_path, text), _row("ECR.1"))
    assert new.endswith(
        'Properties: {RepositoryName: app, "ImageScanningConfiguration": {"ScanOnPush": true}}\n'
    )


@pytest.mark.parametrize(
    ("exports", "expect"),
    [
        ("      EnableCloudwatchLogsExports:\n        - error\n", "        - postgresql\n"),
        ("      EnableCloudwatchLogsExports: [error]\n", "[error, postgresql]"),
        ("", "EnableCloudwatchLogsExports: [postgresql]"),
    ],
)
def test_includes_appends_to_list(tmp_path: Path, exports: str, expect: str) -> None:
    text = (
        "Resources:\n  R:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        f"      Engine: postgres\n{exports}"
    )
    res = _res(tmp_path, text)
    new, _, _ = attr_edit(res, _row("RDS.36"))
    assert expect in new
    assert "error" not in exports or "error" in _props(new)["EnableCloudwatchLogsExports"]
    assert "postgresql" in _props(new)["EnableCloudwatchLogsExports"]


def test_at_least_reads_string_numbers(tmp_path: Path) -> None:
    text = (
        "Resources:\n  R:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        '      BackupRetentionPeriod: "3"\n'
    )
    new, _, _ = attr_edit(_res(tmp_path, text), _row("RDS.11"))
    assert _props(new)["BackupRetentionPeriod"] == 7
    ok = text.replace('"3"', '"14"')
    with pytest.raises(StageStop, match="already meets"):
        cfn.attr_diff(tmp_path, _res(tmp_path, ok), _row("RDS.11"))


@pytest.mark.parametrize(
    "props",
    [
        "      DeletionProtection: !If [IsProd, true, false]\n",
        "      DeletionProtection: {Ref: Protect}\n",
    ],
)
def test_intrinsic_target_stops(tmp_path: Path, props: str) -> None:
    text = f"Resources:\n  R:\n    Type: AWS::RDS::DBInstance\n    Properties:\n{props}"
    with pytest.raises(StageStop, match="not a literal value"):
        attr_edit(_res(tmp_path, text), _row("RDS.8"))


def test_intrinsic_parent_stops(tmp_path: Path) -> None:
    text = (
        "Resources:\n  R:\n    Type: AWS::DynamoDB::Table\n    Properties:\n"
        "      PointInTimeRecoverySpecification: !If [IsProd, {PointInTimeRecoveryEnabled: true},"
        " !Ref AWS::NoValue]\n"
    )
    with pytest.raises(StageStop, match="not a literal value"):
        attr_edit(_res(tmp_path, text), _row("DynamoDB.2"))


def test_when_guards(tmp_path: Path) -> None:
    mysql = (
        "Resources:\n  R:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      Engine: mysql\n"
    )
    with pytest.raises(StageStop, match="doesn't apply here: Engine is 'mysql'"):
        attr_edit(_res(tmp_path, mysql), _row("RDS.36"))
    cmk = (
        "Resources:\n  R:\n    Type: AWS::SQS::Queue\n    Properties:\n"
        "      KmsMasterKeyId: alias/app\n"
    )
    with pytest.raises(StageStop, match="KmsMasterKeyId is 'alias/app'"):
        attr_edit(_res(tmp_path, cmk), _row("SQS.1"))
    spec = "Resources:\n  R:\n    Type: AWS::KMS::Key\n    Properties:\n      KeySpec: !Ref Spec\n"
    with pytest.raises(StageStop, match="not a literal value"):
        attr_edit(_res(tmp_path, spec), _row("KMS.4"))
    plain = "Resources:\n  R:\n    Type: AWS::KMS::Key\n    Properties:\n      Description: k\n"
    new, _, _ = attr_edit(_res(tmp_path, plain), _row("KMS.4"))
    assert _props(new)["EnableKeyRotation"] is True


def test_validate_fails_when_nothing_changed(tmp_path: Path) -> None:
    text = "Resources:\n  R:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      Engine: x\n"
    res = _res(tmp_path, text)
    diff = cfn.validate._diff(tmp_path, res, text, "noop", "test")
    report = cfn.validate_attr(res, diff, _row("RDS.8"), Config(), None, offline=True)
    by_id = {c.id: c for c in report.checks}
    assert by_id["template_scope"].result is CheckResult.FAIL
    assert by_id["recheck"].result is CheckResult.FAIL
    assert attr_unmet(res, _row("RDS.8")) == ["DeletionProtection = true"]


# --- pipeline


def test_dry_run_fixes_rds_instance_in_template(repo: Path) -> None:
    record = run_fix(str(RDS8), repo, load_config(repo)[0])
    assert record.result == "DRY RUN", record.stages
    assert record.location is not None and record.location.address == "cfn.data.OrdersDb"
    assert record.diff is not None
    new = record.diff.files[0].new_content
    assert "DeletionProtection: true # flipped on by hand during the migration" in new
    assert record.diff.generator == "template:config_attribute@1:cloudformation"
    checks = {c.id: c for c in record.validation.checks} if record.validation else {}
    assert checks["recheck"].result is CheckResult.PASS
    assert checks["template_scope"].result is CheckResult.PASS
    assert checks["changeset"].result is CheckResult.SKIPPED and not checks["changeset"].required


def _fake_aws(body: str) -> Any:
    class Cfn:
        def get_template(self, **kw: Any) -> dict[str, Any]:
            return {"TemplateBody": body}

    return lambda service: ReadOnlyClient(Cfn(), service)


def test_check_mode_uses_deployed_template(repo: Path) -> None:
    body = (repo / "templates/data.yaml").read_text("utf-8")
    config, _ = load_config(repo)
    record = run_fix(str(RDS8), repo, config, Context(mode="check", aws=_fake_aws(body)))
    assert record.result == "VALIDATED", record.stages

    drifted = body.replace("db.t4g.micro", "db.t4g.small")
    record = run_fix(str(RDS8), repo, config, Context(mode="check", aws=_fake_aws(drifted)))
    assert record.result == "STOPPED"
    assert any("differs from stack data" in s.summary for s in record.stages)


def test_unmapped_control_stops_unknown(repo: Path, tmp_path: Path) -> None:
    finding = tmp_path / "elb4.json"
    finding.write_text(RDS8.read_text("utf-8").replace("RDS.8", "ELB.4"), "utf-8")
    record = run_fix(str(finding), repo, load_config(repo)[0])
    assert record.result == "STOPPED" and record.exit_code == 3
    assert any("no CloudFormation property mapping" in s.summary for s in record.stages)
