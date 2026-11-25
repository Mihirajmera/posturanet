"""The plugin API is a promise to PosturaNet Pro: these names must keep existing."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from posturanet import plugin_api
from posturanet.cli import app as cli


def test_plugin_api_names_are_pinned() -> None:
    assert sorted(plugin_api.__all__) == sorted(
        [
            "API_VERSION",
            "GATE_EXIT",
            "AsciiOpt",
            "FormatOpt",
            "OutputFormat",
            "RepoOpt",
            "StateOpt",
            "WindowOpt",
            "examples",
            "fail",
            "frame",
            "publish_check",
            "window",
        ]
    )
    for name in plugin_api.__all__:
        assert getattr(plugin_api, name) is not None
    assert plugin_api.GATE_EXIT == {"PASS": 0, "BLOCK": 5, "UNKNOWN": 3}


def test_pro_command_without_pro_says_where_it_comes_from(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("importlib.metadata.entry_points", lambda group: [])
    cli._load_plugins()
    for args in (
        ["contract", "refresh", "--all", "--repo", "x"],
        ["evidence", "record", "run.json"],
        ["gate"],
    ):
        out = CliRunner().invoke(cli.app, args)
        assert out.exit_code == 6, args
        assert "part of PosturaNet Pro" in out.output and cli.PRO_URL in out.output
    # hidden: free help doesn't list them
    help_out = CliRunner().invoke(cli.app, ["contract", "--help"]).output
    assert "refresh" not in help_out and "live" not in help_out
    root_help = CliRunner().invoke(cli.app, ["--help"]).output
    assert "triggers" not in root_help and " gate " not in root_help


def test_a_real_plugin_command_wins_over_the_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    import typer

    class _EP:
        name = "pro"

        @staticmethod
        def load():  # type: ignore[no-untyped-def]
            def register(apps: dict[str, typer.Typer]) -> None:
                @apps["contract"].command("live")
                def live() -> None:
                    typer.echo("real live")

            return register

    monkeypatch.setattr("importlib.metadata.entry_points", lambda group: [_EP()])
    cli._load_plugins()
    out = CliRunner().invoke(cli.app, ["contract", "live"])
    assert out.exit_code == 0 and "real live" in out.output
