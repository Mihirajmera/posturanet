"""The PosturaNet banner for interactive terminals (design system section 10.1).

The logo (white cloud, blue P) beside the block-letter wordmark (green, with the O and NET in
red), then every command with an example, on the same rail and box frame as every other command
(`output/frame.py`).

Shown only to a person at a terminal: never in JSON, piped output, CI, the MCP server or
agent hooks, so nothing that parses PosturaNet's output ever sees it.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from functools import partial
from typing import TextIO

from posturanet import __version__
from posturanet.output.frame import Frame
from posturanet.output.style import Style
from posturanet.output.symbols import to_ascii

_LETTERS = {
    "P": ("██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "),
    "O": (" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "),
    "S": ("███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"),
    "T": ("████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "),
    "U": ("██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "),
    "R": ("██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"),
    "A": (" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"),
    "N": ("███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"),
    "E": ("███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"),
}
WORDMARK = tuple("".join(_LETTERS[c][row] for c in "POSTURANET") for row in range(6))
WIDTH = max(len(row) for row in WORDMARK)
# The logo SVG (cloud, P and arrow) rasterized to half blocks.
LOGO = (
    "           ▄▄▄▄▄▄",
    "        ▄██▀▀▀▀▀▀██▄",
    "    ▄▄▄▄█▀        ▀█▄▄▄▄",
    " ▄██▀▀▀▀▀  ▄██▀▀████▀▀▀▀██▄",
    " ██       ██      ▀█▄    ██",
    " ██       ██       ██    ██",
    " ██       ██      ▄█▀    ██",
    "  ██▄     ██ ▄▄████▀   ▄██",
    "   ▀▀██▄▄▄███████ ▄▄▄██▀▀",
    "       ▀▀▀██    ▀ ▀▀▀",
    "          ██",
    "          ▀▀",
)
LOGO_WIDTH = 28
SIDE_BY_SIDE = LOGO_WIDTH + 3 + WIDTH  # logo, gap, wordmark
TAGLINE = "Fixes cloud security issues without breaking prod."
# (section, ((example command, what it does), ...)): every command, with one it's safe to copy.
START = (
    ("Set up", (
        ("posturanet init > policy.json", "the read-only IAM policy for PosturaNet's role"),
        ("posturanet connect", "hook up your scanner, coding agent and CI"),
    )),
    ("Bring your findings", (
        ("posturanet findings list scan.json", "what PosturaNet can fix in a scan"),
        ("posturanet findings split scan.json --out findings/", "one file per finding"),
        ("posturanet findings pull-plans --out plans.json", "Security Hub remediation plans"),
    )),
    ("Fix", (
        ("posturanet fix finding.json --dry-run --repo infra/", "see the fix; changes nothing"),
        ("posturanet fix finding.json --repo infra/ --open-pr", "open the PR; a person merges"),
        ("posturanet fixes show RDS.8", "what a control's fix changes"),
    )),
    ("Keep it fixed", (
        ("posturanet contract check --source --repo infra/", "check an edit against contracts"),
        ("posturanet verify owner/repo#123", "after merge: did the fix hold?"),
    )),
)  # fmt: skip
_WHITE, _BLUE = (0xFF, 0xFF, 0xFF), (0x00, 0x66, 0xFF)  # cloud, P
_GREEN, _RED = (0x2F, 0xBF, 0x71), (0xE5, 0x48, 0x4D)  # design-system success, critical
_XTERM = {_WHITE: 15, _BLUE: 27, _GREEN: 35, _RED: 167}
_RED_LETTERS = {1, 7, 8, 9}  # the O, and NET, of POSTURANET
_WORD_COLORS = [
    _RED if i in _RED_LETTERS else _GREEN
    for i, c in enumerate("POSTURANET")
    for _ in range(len(_LETTERS[c][0]))
]
_CI_VARS = ("CI", "GITHUB_ACTIONS", "BUILDKITE", "GITLAB_CI", "JENKINS_URL", "TF_BUILD")


def allowed(stream: TextIO) -> bool:
    """A person at a terminal, not a pipe, CI job or opt-out."""
    if os.environ.get("POSTURANET_NO_BANNER") or any(os.environ.get(v) for v in _CI_VARS):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _color_mode() -> str:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return "none"
    if os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit") or os.environ.get(
        "WT_SESSION"
    ):
        return "truecolor"
    return "256"


def _logo_color(row: int, col: int) -> tuple[int, int, int]:
    """The P (its bowl and stem) is blue; everything else is the white cloud."""
    if 3 <= row <= 7:
        return _BLUE if 10 <= col <= 20 else _WHITE
    stem = {8: (10, 11), 9: (9, 10)}.get(row, (0, LOGO_WIDTH))  # rows 10-11: only the stem
    return _BLUE if stem[0] <= col <= stem[1] else _WHITE


def _paint(line: str, color_at: Callable[[int], tuple[int, int, int]], mode: str) -> str:
    if mode == "none":
        return line
    out = []
    for col, ch in enumerate(line):
        if ch == " ":
            out.append(ch)
            continue
        rgb = color_at(col)
        if mode == "truecolor":
            out.append(f"[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m{ch}")
        else:
            out.append(f"[38;5;{_XTERM[rgb]}m{ch}")
    return "".join(out) + "[0m"


def _art(mode: str, width: int | None) -> list[str]:
    """Logo beside the wordmark when it fits, stacked when only the wordmark fits, else the logo."""
    logo = [_paint(r, partial(_logo_color, i), mode) for i, r in enumerate(LOGO)]
    word = [_paint(r, _WORD_COLORS.__getitem__, mode) for r in WORDMARK]
    if width is None or width >= SIDE_BY_SIDE:
        top = (len(LOGO) - len(WORDMARK)) // 2
        rows = []
        for i, (raw, painted) in enumerate(zip(LOGO, logo, strict=True)):
            j = i - top
            right = word[j] if 0 <= j < len(word) else ""
            rows.append((painted + " " * (LOGO_WIDTH - len(raw)) + "   " + right).rstrip())
        return rows
    if width >= WIDTH + 2:
        return [*logo, "", *word]
    return logo if width >= LOGO_WIDTH + 2 else []


def render(*, ascii_mode: bool = False, color: str | None = None, width: int | None = None) -> str:
    """The banner text. The art needs Unicode and room; without either it is left out."""
    mode = color or _color_mode()
    frame = Frame(ascii_mode, Style(mode != "none"), width)
    art = [] if ascii_mode else _art(mode, width)
    lines = [*(r.rstrip() for r in art), ""] if art else []
    lines += frame.open(f"{frame.style('bold', 'PosturaNet')} {__version__} · {TAGLINE}")
    cmd_width = max(len(cmd) for _, rows in START for cmd, _ in rows)
    rows: list[str] = []
    for section, examples in START:
        rows += [*([""] if rows else []), frame.style("bold", section)]
        rows += [f"{frame.style('accent', cmd.ljust(cmd_width))}  {what}" for cmd, what in examples]
    lines += frame.box("Start here", rows)
    lines += frame.close("Each command: posturanet <command> --help shows more examples")
    text = "\n".join(lines) + "\n\n"
    return to_ascii(text) if ascii_mode else text
