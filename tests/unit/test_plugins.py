"""Plugin entry points (`posturanet.plugins`) and the live-check reads Pro needs."""

from __future__ import annotations

from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from posturanet.aws.readonly import iam_action, iam_policy, is_allowed
from posturanet.cli import app as cli


class _EP:
    def __init__(self, name: str, target: Any) -> None:
        self.name, self._target = name, target

    def load(self) -> Any:
        if isinstance(self._target, Exception):
            raise self._target
        return self._target


def test_plugin_adds_a_command_and_a_broken_one_only_warns(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: dict[str, typer.Typer] = {}

    def register(apps: dict[str, typer.Typer]) -> None:
        seen.update(apps)

        @apps["contract"].command("hello-plugin")
        def hello() -> None:
            typer.echo("hi from a plugin")

    eps = [_EP("broken", ImportError("no module named x")), _EP("good", register)]
    monkeypatch.setattr("importlib.metadata.entry_points", lambda group: eps)
    cli._load_plugins()
    assert set(seen) == {"root", "contract"}
    assert "plugin 'broken' not loaded" in capsys.readouterr().err
    out = CliRunner().invoke(cli.app, ["contract", "hello-plugin"])
    assert out.exit_code == 0 and "hi from a plugin" in out.output
    # free commands still work after a broken plugin
    assert CliRunner().invoke(cli.app, ["--help"]).exit_code == 0


def test_live_check_reads_are_allowlisted_and_in_the_policy() -> None:
    assert iam_action("s3control", "get_public_access_block") == "s3:GetAccountPublicAccessBlock"
    assert iam_action("s3", "get_bucket_policy") == "s3:GetBucketPolicy"
    actions = {a for s in iam_policy()["Statement"] for a in s["Action"]}
    for a in ("s3:GetAccountPublicAccessBlock", "s3:GetBucketPolicy"):
        assert is_allowed(a) and a in actions
    assert not is_allowed("s3:PutAccountPublicAccessBlock")
    assert not is_allowed("s3:PutBucketPolicy")
