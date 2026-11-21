"""Plugin entry points (`posturanet.plugins`) and the live-check reads Pro needs."""

from __future__ import annotations

from pathlib import Path
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


def test_s3_use_reason_is_written_and_read_back(tmp_path: Path) -> None:
    from datetime import date

    from posturanet.models import Confidence
    from posturanet.models.contract import ObservedMeta, ObservedWindow
    from posturanet.models.s3 import S3Contract, S3Use
    from posturanet.s3fix import contract as s3contract

    use = S3Use(
        requester="arn:aws:iam::123456789012:role/batch",
        kind="in_account",
        count=1,
        last_seen=date(2026, 7, 1),
        reason="not seen 2026-08-01..2026-10-29; delete only if retired",
    )
    c = S3Contract(
        resource="aws_s3_bucket_public_access_block.assets",
        observed=ObservedMeta(
            source="s3_access_logs",
            window=ObservedWindow(start=date(2026, 8, 1), end=date(2026, 10, 29), days=89),
            confidence=Confidence.HIGH,
        ),
        must_keep=[use],
    )
    path = tmp_path / "c.yaml"
    s3contract.write(path, c)
    loaded = s3contract.load(path)
    assert loaded is not None and loaded.must_keep[0].reason == use.reason
