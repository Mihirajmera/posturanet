from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from posturanet.cli.app import app
from posturanet.connect import BY_NAME, TARGETS, integrations_dir, write

runner = CliRunner()


def test_every_target_file_exists() -> None:
    root = integrations_dir()
    for t in TARGETS:
        assert t.steps
        for src, _ in t.files:
            assert (root / src).is_file(), src


def test_write_never_overwrites_and_appends_agents_md(tmp_path: Path) -> None:
    cursor = BY_NAME["cursor"]
    assert {o for _, o in write(cursor, tmp_path)} == {"written"}
    (tmp_path / ".cursor/mcp.json").write_text("mine", encoding="utf-8")
    assert {o for _, o in write(cursor, tmp_path)} == {"exists, left as is"}
    assert (tmp_path / ".cursor/mcp.json").read_text(encoding="utf-8") == "mine"

    (tmp_path / "AGENTS.md").write_text("# repo\n", encoding="utf-8")
    assert write(BY_NAME["other"], tmp_path) == [("AGENTS.md", "appended")]
    text = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert text.startswith("# repo\n") and "PosturaNet" in text
    assert write(BY_NAME["other"], tmp_path)[0][1].startswith("already mentions")


def test_cli(tmp_path: Path) -> None:
    listed = runner.invoke(app, ["connect", "--ascii"])
    assert listed.exit_code == 0 and "prowler" in listed.output and "cursor" in listed.output
    shown = runner.invoke(app, ["connect", "Prowler", "--ascii"])
    assert shown.exit_code == 0 and "json-ocsf" in shown.output
    assert runner.invoke(app, ["connect", "nope"]).exit_code == 2
    assert (
        runner.invoke(app, ["connect", "prowler", "--write", "--repo", str(tmp_path)]).exit_code
        == 2
    )
    wrote = runner.invoke(app, ["connect", "github", "--write", "--repo", str(tmp_path), "--ascii"])
    assert wrote.exit_code == 0 and (tmp_path / ".github/workflows/posturanet-check.yml").is_file()


def test_help_has_examples() -> None:
    for cmd in (["fix"], ["connect"], ["findings", "list"], ["contract", "check"], ["verify"]):
        out = runner.invoke(app, [*cmd, "--help"]).output
        assert "Examples:" in out and "$ posturanet" in out, cmd
