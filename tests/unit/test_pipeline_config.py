from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from fakes import ConfigTerraform, FakeGitHub
from posturanet.deliver import GitHub
from posturanet.models import StageStatus
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix

FIXTURES = Path(__file__).parent.parent / "fixtures"
RDS = str(FIXTURES / "findings" / "rds_deletion_protection.json")
PITR = str(FIXTURES / "findings" / "dynamodb_pitr.json")
IAM7 = str(FIXTURES / "findings" / "iam_password_policy.json")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    out = tmp_path / "repo"
    shutil.copytree(FIXTURES / "tf" / "config", out)
    return out


def _status(record: Any) -> dict[str, StageStatus]:
    return {s.name: s.status for s in record.stages}


def _rds_tf(**kw: Any) -> ConfigTerraform:
    return ConfigTerraform(
        "aws_db_instance.orders",
        "aws_db_instance",
        ["deletion_protection"],
        before={"identifier": "orders", "deletion_protection": False},
        **kw,
    )


def test_dry_run_fixes_offline_and_writes_nothing(repo: Path) -> None:
    config, _ = load_config(repo)
    before = (repo / "main.tf").read_bytes()
    record = run_fix(RDS, repo, config, Context(mode="dry-run", terraform=_rds_tf()))
    assert record.result == "DRY RUN", record.stages
    status = _status(record)
    assert status["evidence"] is StageStatus.SKIPPED
    assert status["fix"] is StageStatus.OK
    assert status["validate"] is StageStatus.WARN
    assert record.diff is not None and record.diff.summary == "deletion_protection = true"
    assert record.diff.generator == "template:config_attribute@1"
    assert (repo / "main.tf").read_bytes() == before


def test_check_mode_validates_with_plan(repo: Path) -> None:
    config, _ = load_config(repo)
    tf = _rds_tf()
    record = run_fix(RDS, repo, config, Context(mode="check", terraform=tf))
    assert record.result == "VALIDATED", record.stages
    assert record.exit_code == 0
    assert tf.calls == ["fmt", "fmt", "init", "validate", "plan"]
    assert record.validation is not None
    assert {c.id: c.result.value for c in record.validation.checks if c.required} == {
        "guardrails": "pass",
        "recheck": "pass",
        "fmt": "pass",
        "validate": "pass",
        "plan_scope": "pass",
        "plan_matches": "pass",
    }


def test_nested_block_and_account_scope(repo: Path) -> None:
    config, _ = load_config(repo)
    tf = ConfigTerraform(
        "aws_dynamodb_table.events", "aws_dynamodb_table", ["point_in_time_recovery.enabled"]
    )
    record = run_fix(PITR, repo, config, Context(mode="check", terraform=tf))
    assert record.result == "VALIDATED", record.stages

    paths = [
        "require_uppercase_characters",
        "require_lowercase_characters",
        "require_numbers",
        "require_symbols",
        "minimum_password_length",
    ]
    tf = ConfigTerraform(
        "aws_iam_account_password_policy.strict",
        "aws_iam_account_password_policy",
        paths,
        before={"minimum_password_length": 10, "require_numbers": True},
    )
    record = run_fix(IAM7, repo, config, Context(mode="check", terraform=tf))
    assert record.result == "VALIDATED", record.stages
    assert record.location is not None
    assert record.location.address == "aws_iam_account_password_policy.strict"
    assert any("type matched" in r for r in record.location.reasoning)
    fix_stage = next(s for s in record.stages if s.name == "fix")
    assert "require_numbers = true" in " ".join(fix_stage.details)  # already set, left alone


def test_open_pr_and_idempotency(repo: Path) -> None:
    config, _ = load_config(repo)
    fake = FakeGitHub({"main.tf": (repo / "main.tf").read_text(encoding="utf-8")})
    ctx = Context(
        mode="open-pr", terraform=_rds_tf(), github=GitHub("t", "acme/infra", fake.client())
    )
    record = run_fix(RDS, repo, config, ctx)
    assert record.result == "OPENED", record.stages
    pr = fake.prs[0]
    assert pr["head"]["ref"].startswith("posturanet/config/rds-8-orders-")
    assert "deletion_protection = true" in fake.files[(pr["head"]["ref"], "main.tf")]
    assert pr["title"].startswith("🔒 PosturaNet: ") and "(RDS.8)" in pr["title"]
    assert len(pr["title"]) <= 72
    assert "<!-- posturanet:key=" in pr["body"] and "guarantee of production" in pr["body"]

    writes = len(fake.writes)
    again = run_fix(RDS, repo, config, ctx)
    assert "PR already open" in again.stages[-1].summary
    assert len(fake.writes) == writes and len(fake.prs) == 1


def test_already_compliant_code_is_drift(repo: Path) -> None:
    tf_file = repo / "main.tf"
    tf_file.write_text(
        tf_file.read_text(encoding="utf-8").replace(
            "  skip_final_snapshot = true\n",
            "  skip_final_snapshot = true\n  deletion_protection = true\n",
            1,
        ),
        encoding="utf-8",
    )
    config, _ = load_config(repo)
    record = run_fix(RDS, repo, config, Context(mode="dry-run", terraform=_rds_tf()))
    assert record.result == "STOPPED"
    assert "drifted" in next(s for s in record.stages if s.name == "fix").summary


def test_plan_changing_other_attributes_fails(repo: Path) -> None:
    config, _ = load_config(repo)
    tf = _rds_tf(extra_after={"identifier": "orders-new"})
    record = run_fix(RDS, repo, config, Context(mode="check", terraform=tf))
    assert record.result == "STOPPED" and record.exit_code == 4
    assert "identifier" in next(s for s in record.stages if s.name == "validate").summary


def test_plan_touching_another_resource_fails(repo: Path) -> None:
    config, _ = load_config(repo)
    other = {"address": "aws_kms_key.x", "change": {"actions": ["delete"]}}
    record = run_fix(
        RDS, repo, config, Context(mode="check", terraform=_rds_tf(extra_changes=[other]))
    )
    assert record.result == "STOPPED" and record.exit_code == 4


def test_variable_elsewhere_in_block_is_fine(repo: Path) -> None:
    # RDS.8 has no `when` on engine, so a variable there doesn't block the fix.
    tf_file = repo / "main.tf"
    text = tf_file.read_text(encoding="utf-8")
    tf_file.write_text(text.replace('"postgres"', "var.engine"), encoding="utf-8")
    config, _ = load_config(repo)
    record = run_fix(RDS, repo, config, Context(mode="dry-run", terraform=_rds_tf()))
    assert record.result == "DRY RUN", record.stages


def test_when_on_a_variable_stops(repo: Path, tmp_path: Path) -> None:
    tf_file = repo / "main.tf"
    text = tf_file.read_text(encoding="utf-8")
    tf_file.write_text(text.replace('"postgres"', "var.engine"), encoding="utf-8")
    finding = tmp_path / "rds36.json"
    finding.write_text(
        Path(RDS).read_text(encoding="utf-8").replace("RDS.8", "RDS.36"), encoding="utf-8"
    )
    config, _ = load_config(repo)
    record = run_fix(str(finding), repo, config, Context(mode="dry-run", terraform=_rds_tf()))
    assert record.result == "STOPPED"
    assert "engine is not a literal" in next(s for s in record.stages if s.name == "fix").summary


def test_contract_build_refuses_attribute_fixes(repo: Path) -> None:
    config, _ = load_config(repo)
    ctx = Context(mode="dry-run", terraform=_rds_tf(), stop_after="contract")
    record = run_fix(RDS, repo, config, ctx)
    assert record.result == "STOPPED"
    assert "no behavior contract" in record.why  # type: ignore[operator]
