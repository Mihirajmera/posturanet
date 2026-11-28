"""FR-55: plans that delete data, and destroy commands from agents, stop for a human."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from posturanet.destructive import destructive_command
from posturanet.gate import check_plan
from posturanet.hooks import claude_code
from posturanet.models.config import load_config
from posturanet.output.console import render_gate


def _plan(*changes: dict[str, Any]) -> dict[str, Any]:
    return {"format_version": "1.2", "resource_changes": list(changes)}


def _rc(address: str, actions: list[str], before: Any = None, after: Any = None) -> dict[str, Any]:
    return {
        "address": address,
        "mode": "managed",
        "type": address.split(".")[0],
        "change": {"actions": actions, "before": before, "after": after, "after_unknown": {}},
    }


def test_deleting_a_database_blocks(tmp_repo: Path) -> None:
    config, _ = load_config(tmp_repo)
    plan = _plan(
        _rc("aws_db_instance.main", ["delete"], {"identifier": "main"}),
        _rc("aws_instance.web", ["delete"]),  # stateless: not this rule's business
    )
    result = check_plan(plan, tmp_repo, config)
    assert result.status == "BLOCK"
    assert result.summary == "BLOCK · this change would destroy 1 resource"
    (r,) = result.results
    assert r.address == "aws_db_instance.main" and r.rule == "destructive"
    assert r.reasons == ["the plan deletes this aws_db_instance (the data in it is lost)"]
    text = render_gate(result, ascii_mode=True, framed=False)
    assert "contracts.allow_destroy" in text and "keep the access" not in text


def test_replace_and_guards_block(tmp_repo: Path) -> None:
    config, _ = load_config(tmp_repo)
    plan = _plan(
        _rc("aws_s3_bucket.logs", ["delete", "create"]),
        _rc(
            "aws_rds_cluster.db",
            ["update"],
            {"deletion_protection": True, "skip_final_snapshot": False, "backup_retention_period": 7},
            {"deletion_protection": False, "skip_final_snapshot": True, "backup_retention_period": 0},
        ),
        _rc("aws_rds_cluster.ok", ["update"], {"backup_retention_period": 7}, {"backup_retention_period": 14}),
    )  # fmt: skip
    result = check_plan(plan, tmp_repo, config)
    by = {r.address: r.reasons for r in result.results}
    assert set(by) == {"aws_s3_bucket.logs", "aws_rds_cluster.db"}
    assert by["aws_s3_bucket.logs"] == ["the plan replaces this aws_s3_bucket (the data in it is lost)"]  # fmt: skip
    assert len(by["aws_rds_cluster.db"]) == 3
    assert result.summary == "BLOCK · this change would destroy 2 resources"


def test_allow_destroy_and_opt_out(tmp_repo: Path) -> None:
    cfg = tmp_repo / ".posturanet.yml"
    base = cfg.read_text(encoding="utf-8") if cfg.exists() else "version: 1\n"
    plan = _plan(_rc("aws_dynamodb_table.old", ["delete"]), _rc("aws_kms_key.k", ["delete"]))
    cfg.write_text(
        base + "contracts:\n  allow_destroy: ['aws_dynamodb_table.*']\n", encoding="utf-8"
    )
    config, _ = load_config(tmp_repo)
    assert [r.address for r in check_plan(plan, tmp_repo, config).results] == ["aws_kms_key.k"]
    cfg.write_text(base + "contracts:\n  destructive: false\n", encoding="utf-8")
    config, _ = load_config(tmp_repo)
    assert check_plan(plan, tmp_repo, config).status == "PASS"


@pytest.mark.parametrize(
    "command",
    [
        "terraform destroy",
        "cd infra && terraform -chdir=prod destroy -auto-approve",
        "tofu apply -auto-approve",
        "terraform apply -destroy",
        "pulumi destroy --yes",
        "npx cdk destroy MyStack",
        "aws rds delete-db-instance --db-instance-identifier main",
        "aws s3 rm s3://bucket/ --recursive",
        "aws s3 rb s3://bucket --force",
    ],
)
def test_destroy_commands_are_recognised(command: str) -> None:
    assert destructive_command(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        "terraform plan -destroy -out plan.bin",
        "terraform apply plan.bin",
        "aws s3 ls",
        "echo destroy",
        "git rm -r old",
    ],  # fmt: skip
)
def test_safe_commands_pass(command: str) -> None:
    assert destructive_command(command) is None


def test_hook_asks_before_destroy(tmp_path: Path) -> None:
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "terraform destroy"}}  # fmt: skip
    out = json.loads(claude_code(json.dumps(event), tmp_path))["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse" and out["permissionDecision"] == "ask"
    assert "destroys every resource" in out["permissionDecisionReason"]
    event["tool_input"] = {"command": "terraform plan"}
    assert claude_code(json.dumps(event), tmp_path) == ""
    event["tool_name"] = "Read"
    event["tool_input"] = {"command": "terraform destroy"}
    assert claude_code(json.dumps(event), tmp_path) == ""
    assert claude_code("not json", tmp_path) == ""
