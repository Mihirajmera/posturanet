"""Terminal colors follow design system 10.3 and never reach pipes, JSON or NO_COLOR."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from typer.testing import CliRunner

from posturanet.cli.app import app
from posturanet.output.style import Style, wants_color

runner = CliRunner()


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_color_only_for_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("NO_COLOR", "FORCE_COLOR", "TERM"):
        monkeypatch.delenv(var, raising=False)
    assert wants_color(_Tty()) is True
    assert wants_color(io.StringIO()) is False
    monkeypatch.setenv("NO_COLOR", "1")
    assert wants_color(_Tty()) is False
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert wants_color(_Tty()) is False


def test_style_is_a_no_op_when_off() -> None:
    assert Style(False)("success", "ok") == "ok"
    assert Style(True)("success", "ok") == "\x1b[32mok\x1b[0m"


def test_forced_color_paints_status_words(
    monkeypatch: pytest.MonkeyPatch, sg_finding_path: Path, basic_repo: Path, flows_path: Path
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    args = ["fix", str(sg_finding_path), "--dry-run", "--repo", str(basic_repo)]
    out = runner.invoke(app, [*args, "--evidence-file", str(flows_path)]).output
    assert "\x1b[32m✓" in out  # ok stages in green
    assert "\x1b[34mDRY RUN\x1b[0m" in out
    assert "\x1b[31m-" in out and "\x1b[32m+" in out  # diff
    assert "\x1b[33m  ! external, review owner" in out


def test_json_and_pipes_stay_plain(
    monkeypatch: pytest.MonkeyPatch, sg_finding_path: Path, basic_repo: Path
) -> None:
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    args = ["fix", str(sg_finding_path), "--dry-run", "--repo", str(basic_repo)]
    assert "\x1b[" not in runner.invoke(app, args).output
    assert "\x1b[" not in runner.invoke(app, [*args, "--format", "json"]).output
