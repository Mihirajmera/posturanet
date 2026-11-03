from __future__ import annotations

import io
import json
import re

import pytest
from typer.testing import CliRunner

from posturanet import __version__
from posturanet.cli.app import app
from posturanet.output import banner

_ENV_OFF = ("POSTURANET_NO_BANNER", "NO_COLOR", *banner._CI_VARS)


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ENV_OFF:
        monkeypatch.delenv(var, raising=False)


def test_logo_rows_fit_and_render_plain() -> None:
    assert all(len(row) <= banner.WIDTH for row in banner.LOGO)
    text = banner.render(color="none")
    assert f"PosturaNet {__version__}" in text and banner.TAGLINE in text
    assert "\x1b[" not in text
    assert "→ posturanet init" in text


def test_colors_and_ascii_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    truecolor = banner.render(color="truecolor")
    blues = [int(b) for b in re.findall(r"\x1b\[38;2;\d+;\d+;(\d+)m", truecolor)]
    assert blues and all(0xF3 <= b <= 0xFF for b in blues)  # inside #3197F3 → #0066FF
    assert "\x1b[38;5;" in banner.render(color="256")
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b[" not in banner.render()
    ascii_text = banner.render(ascii_mode=True)
    assert ascii_text.isascii() and f"PosturaNet {__version__}" in ascii_text


def test_only_for_a_person_at_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    assert banner.allowed(_Tty())
    assert not banner.allowed(io.StringIO())  # piped
    monkeypatch.setenv("CI", "true")
    assert not banner.allowed(_Tty())
    monkeypatch.delenv("CI")
    monkeypatch.setenv("POSTURANET_NO_BANNER", "1")
    assert not banner.allowed(_Tty())


def test_cli_output_stays_parseable() -> None:
    runner = CliRunner()
    bare = runner.invoke(app, [])
    assert bare.exit_code == 0 and "Usage" in bare.output
    assert "▀" not in bare.output  # CliRunner output is not a terminal

    version = runner.invoke(app, ["--version"])
    assert version.output == f"PosturaNet {__version__}\n"

    init = runner.invoke(app, ["init"])
    assert init.exit_code == 0
    json.loads(init.stdout)
