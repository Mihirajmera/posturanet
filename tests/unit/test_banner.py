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


def test_logo_wordmark_and_start_box_render_plain() -> None:
    assert len(banner.WORDMARK) == 6 and all(len(r) == banner.WIDTH for r in banner.WORDMARK)
    assert all(len(r) <= banner.LOGO_WIDTH for r in banner.LOGO)
    text = banner.render(color="none")
    assert f"PosturaNet {__version__}" in text and banner.TAGLINE in text
    assert "[" not in text
    assert banner.WORDMARK[0].rstrip() in text and banner.LOGO[1].strip() in text
    lines = text.splitlines()
    assert lines[len(banner.LOGO) + 1].startswith("┌  ")  # art, blank, then the rail opens
    assert "◇  Start here ─" in text and "posturanet init > policy.json" in text
    for _, examples in banner.START:  # every example in the box
        assert all(cmd in text for cmd, _ in examples)
    assert "└  Each command: posturanet <command> --help" in text


def test_art_fits_the_terminal() -> None:
    side = banner.render(color="none", width=banner.SIDE_BY_SIDE)
    stacked = banner.render(color="none", width=banner.WIDTH + 2)
    assert len(side.splitlines()) < len(stacked.splitlines())  # stacked adds the wordmark rows
    logo_only = banner.render(color="none", width=60)
    assert "█" in logo_only and banner.WORDMARK[0].rstrip() not in logo_only
    assert "╮" not in logo_only  # too narrow for the closed box: right edge dropped
    assert "█" not in banner.render(color="none", width=20)


def test_colors_and_ascii_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    truecolor = banner.render(color="truecolor")
    used = set(re.findall(r"\x1b\[38;2;(\d+;\d+;\d+)m", truecolor))
    assert used == {"255;255;255", "0;102;255", "47;191;113", "229;72;77"}  # cloud, P, green, red
    word = banner._paint(banner.WORDMARK[0], banner._WORD_COLORS.__getitem__, "truecolor")
    assert word.startswith("\x1b[38;2;47;191;113m█")  # P green
    assert "\x1b[38;2;229;72;77m█" in word  # O and NET red
    assert "\x1b[38;5;" in banner.render(color="256")
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b[" not in banner.render()
    ascii_text = banner.render(ascii_mode=True, color="none")
    assert ascii_text.isascii() and f"PosturaNet {__version__}" in ascii_text
    assert ascii_text.startswith("+  PosturaNet")


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
    assert "█" not in bare.output  # CliRunner output is not a terminal

    version = runner.invoke(app, ["--version"])
    assert version.output == f"PosturaNet {__version__}\n"

    init = runner.invoke(app, ["init"])
    assert init.exit_code == 0
    json.loads(init.stdout)
