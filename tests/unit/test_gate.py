from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from fakes import FakeTerraform, plan_for
from posturanet.cli.app import app
from posturanet.evidence import FileSource
from posturanet.gate import check_plan
from posturanet.mcp.server import check_change, explain_finding, propose_fix
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix
from posturanet.synth.sg_rules import Rule

OPEN_22 = Rule("0.0.0.0/0", 22, 22, "tcp")
SOURCES = ["10.0.4.12/32", "10.0.4.37/32", "10.0.5.9/32", "198.51.100.23/32", "203.0.113.7/32"]


def _with_contract(repo: Path, flows: Path, finding: Path) -> None:
    config, _ = load_config(repo)
    run_fix(str(finding), repo, config, Context(mode="check", evidence=FileSource(flows), terraform=FakeTerraform()))  # fmt: skip


def _rules(cidrs: list[str]) -> list[Rule]:
    return [Rule(c, 22, 22, "tcp") for c in cidrs]


def test_gate_pass_block_unknown(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)

    ok = check_plan(plan_for([OPEN_22], _rules(SOURCES)), tmp_repo, config)
    assert ok.status == "PASS" and ok.summary == "PASS · 1 contract checked"

    broken = check_plan(plan_for([OPEN_22], _rules(SOURCES[:-1])), tmp_repo, config)
    assert broken.status == "BLOCK"
    assert broken.results[0].reasons == [
        "breaks must_allow: 203.0.113.7/32 → 22/tcp (draft contract)"
    ]

    reopened = check_plan(plan_for([OPEN_22], [OPEN_22]), tmp_repo, config)
    assert reopened.status == "BLOCK"
    assert any("must_deny: 0.0.0.0/0" in r for r in reopened.results[0].reasons)

    unknown = check_plan(plan_for([OPEN_22], [], after_unknown=True), tmp_repo, config)
    assert unknown.status == "UNKNOWN"

    no_contract = check_plan(plan_for([], [], address="aws_security_group.other"), tmp_repo, config)
    assert no_contract.status == "PASS" and no_contract.results == []


def test_contract_check_cli_exit_5(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path, tmp_path: Path
) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(plan_for([OPEN_22], _rules(SOURCES[:1]))))
    result = CliRunner().invoke(app, ["contract", "check", "--plan", str(plan), "--repo", str(tmp_repo), "--ascii"])  # fmt: skip
    assert result.exit_code == 5, result.output
    assert "BLOCK - this change would break 1 contract" in result.output
    assert "[x] module.bastion.aws_security_group.this" in result.output


def test_mcp_tools_are_read_only(basic_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    before = sorted(p.as_posix() for p in basic_repo.rglob("*"))
    explained = explain_finding(str(sg_finding_path), str(basic_repo), str(flows_path))
    assert explained["result"] == "CONTRACT"
    assert explained["location"]["owners"] == ["@example-org/platform-network"]
    assert "hours_histogram" not in explained["observations"]["items"][0]
    proposed = propose_fix(str(sg_finding_path), str(basic_repo), str(flows_path))
    assert proposed["result"] == "DRY RUN"
    assert proposed["summary"].startswith("Result DRY RUN")
    assert "10.0.4.12/32" in proposed["diff"]["files"][0]["unified_diff"]
    assert sorted(p.as_posix() for p in basic_repo.rglob("*")) == before

    bad = check_change("{not json", str(basic_repo))
    assert bad["status"] == "UNKNOWN"
