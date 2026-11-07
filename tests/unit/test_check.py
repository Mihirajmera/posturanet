"""R1.5: offline source check, check runs, CLI flags, Claude Code hook, MCP source mode."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
from typer.testing import CliRunner

from fakes import FakeTerraform, plan_for
from posturanet.cli.app import app
from posturanet.deliver.checks import CHECK_NAME, payload, publish
from posturanet.deliver.github import GitHub
from posturanet.evidence import FileSource
from posturanet.gate import check_plan, check_source
from posturanet.hooks import claude_code
from posturanet.mcp.server import check_change
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix
from posturanet.synth.sg_rules import Rule

SOURCES = ["10.0.4.12/32", "10.0.4.37/32", "10.0.5.9/32", "198.51.100.23/32", "203.0.113.7/32"]
MODULE = Path("modules/bastion/main.tf")


def _with_contract(repo: Path, flows: Path, finding: Path) -> None:
    config, _ = load_config(repo)
    run_fix(str(finding), repo, config, Context(mode="check", evidence=FileSource(flows), terraform=FakeTerraform()))  # fmt: skip


def _set_cidrs(repo: Path, cidrs: list[str]) -> None:
    path = repo / MODULE
    listed = ", ".join(f'"{c}"' for c in cidrs)
    text = path.read_text(encoding="utf-8").replace('["0.0.0.0/0"]', f"[{listed}]")
    path.write_text(text, encoding="utf-8")


def _event(path: Path) -> str:
    return json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(path)},
        }
    )


def test_source_check_blocks_open_group_and_passes_fix(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)

    still_open = check_source(tmp_repo, config)
    assert still_open.status == "BLOCK" and still_open.mode == "source"
    r = still_open.results[0]
    assert r.address == "module.bastion.aws_security_group.this"
    assert r.source_file == MODULE.as_posix() and r.source_line == 5
    assert any("must_deny: 0.0.0.0/0 → 22/tcp" in reason for reason in r.reasons)
    deny = next(v for v in r.violations if "must_deny" in v.message)
    contract_lines = (tmp_repo / r.contract_file).read_text(encoding="utf-8").splitlines()
    assert deny.contract_line is not None
    assert "0.0.0.0/0" in contract_lines[deny.contract_line - 1]

    _set_cidrs(tmp_repo, SOURCES)
    assert check_source(tmp_repo, config).status == "PASS"

    (tmp_repo / MODULE).write_text(
        (tmp_repo / MODULE).read_text(encoding="utf-8").replace(', "203.0.113.7/32"', ""),
        encoding="utf-8",
    )
    cut = check_source(tmp_repo, config)
    assert cut.status == "BLOCK"
    assert cut.results[0].reasons == ["breaks must_allow: 203.0.113.7/32 → 22/tcp (draft contract)"]


def test_source_check_unknown_and_file_filter(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)
    path = tmp_repo / MODULE
    path.write_text(
        path.read_text(encoding="utf-8").replace('["0.0.0.0/0"]', "var.allowed"), encoding="utf-8"
    )
    unknown = check_source(tmp_repo, config)
    assert unknown.status == "UNKNOWN"
    assert "not a literal value" in unknown.results[0].reasons[0]
    assert unknown.summary == "UNKNOWN · some planned changes can't be judged from the source alone"

    other = check_source(tmp_repo, config, [tmp_repo / "main.tf"])
    assert other.status == "PASS" and other.results == []


def test_plan_check_reports_caused_by(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)
    open22 = Rule("0.0.0.0/0", 22, 22, "tcp")
    result = check_plan(plan_for([open22], [Rule(SOURCES[0], 22, 22, "tcp")]), tmp_repo, config)
    assert result.results[0].caused_by == f"planned ingress in {MODULE.as_posix()}:5"


def test_check_run_payload_and_publish(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)
    result = check_source(tmp_repo, config)
    body = payload(result, "abc123")
    assert body["name"] == CHECK_NAME and body["head_sha"] == "abc123"
    assert body["conclusion"] == "failure"
    assert body["output"]["title"].startswith("BLOCK · this change would break 1 contract")
    assert "caused by: planned ingress in modules/bastion/main.tf:5" in body["output"]["text"]
    paths = {a["path"] for a in body["output"]["annotations"]}
    assert paths == {result.results[0].contract_file, MODULE.as_posix()}

    _set_cidrs(tmp_repo, SOURCES)
    assert payload(check_source(tmp_repo, config), "abc")["conclusion"] == "success"

    sent: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/acme/infra/check-runs"
        sent.append(json.loads(request.content))
        return httpx.Response(201, json={"html_url": "https://github.com/acme/infra/runs/1"})

    gh = GitHub("t", "acme/infra", httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(handler)))  # fmt: skip
    url = publish(gh, check_source(tmp_repo, config), "abc")
    assert url.endswith("/runs/1") and sent[0]["conclusion"] == "success"


def test_unknown_check_run_is_neutral(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)
    result = check_plan(plan_for([], [], after_unknown=True), tmp_repo, config)
    assert result.status == "UNKNOWN"
    assert payload(result, "x")["conclusion"] == "neutral"


def test_cli_source_mode(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    runner = CliRunner()
    blocked = runner.invoke(app, ["contract", "check", "--source", "--repo", str(tmp_repo), "--ascii"])  # fmt: skip
    assert blocked.exit_code == 5, blocked.output
    assert "caused by: planned ingress in modules/bastion/main.tf:5" in blocked.output

    both = runner.invoke(app, ["contract", "check", "--source", "--plan", "x.json", "--repo", str(tmp_repo)])  # fmt: skip
    assert both.exit_code == 2
    neither = runner.invoke(app, ["contract", "check", "--repo", str(tmp_repo)])
    assert neither.exit_code == 2

    no_env = runner.invoke(
        app,
        ["contract", "check", "--source", "--github-check", "--repo", str(tmp_repo)],
        env={"GITHUB_TOKEN": "", "GITHUB_REPOSITORY": "", "GITHUB_SHA": ""},
    )
    assert no_env.exit_code == 2 and "GITHUB_TOKEN" in no_env.output


def test_claude_code_hook(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    module = tmp_repo / MODULE

    blocked = json.loads(claude_code(_event(module), Path("/nonexistent")))
    assert blocked["decision"] == "block"
    assert "must_deny: 0.0.0.0/0" in blocked["reason"]
    assert "Do not edit the contract yourself" in blocked["reason"]

    _set_cidrs(tmp_repo, SOURCES)
    assert claude_code(_event(module), tmp_repo) == ""

    module.write_text(module.read_text(encoding="utf-8").replace('protocol    = "tcp"', "protocol = var.p"), encoding="utf-8")  # fmt: skip
    unknown = json.loads(claude_code(_event(module), tmp_repo))
    assert "could not judge" in unknown["hookSpecificOutput"]["additionalContext"]

    assert claude_code(_event(tmp_repo / ".posturanet.yml"), tmp_repo) == ""
    assert claude_code("not json", tmp_repo) == ""
    assert claude_code(json.dumps({"tool_input": {"file_path": 7}}), tmp_repo) == ""


def test_hook_cli_never_fails(tmp_repo: Path) -> None:
    result = CliRunner().invoke(app, ["hook", "claude-code", "--repo", str(tmp_repo)], input="{}")
    assert result.exit_code == 0 and result.output == ""


def test_mcp_check_change_source_mode(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _with_contract(tmp_repo, flows_path, sg_finding_path)
    before = sorted(p.as_posix() for p in tmp_repo.rglob("*"))
    doc = check_change(repo=str(tmp_repo), files=[MODULE.as_posix()])
    assert doc["status"] == "BLOCK" and doc["mode"] == "source"
    assert doc["results"][0]["violations"][0]["contract_line"] is not None
    assert check_change(repo=str(tmp_repo), files=["main.tf"])["status"] == "PASS"
    assert sorted(p.as_posix() for p in tmp_repo.rglob("*")) == before
