"""The PosturaNet logo for interactive terminals (design system section 10.1).

The pixels are the logo SVG (`posturanet-site/src/app/icon.svg`: cloud, P and arrow)
rasterized to half-block characters, colored with the brand gradient #3197F3 → #0066FF.

Shown only to a person at a terminal: never in JSON, piped output, CI, the MCP server or
agent hooks, so nothing that parses PosturaNet's output ever sees it.
"""

from __future__ import annotations

import os
from typing import TextIO

from posturanet import __version__

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
WIDTH = 28
TAGLINE = "Fixes cloud security issues without breaking prod."
START = (
    ("posturanet init", "read-only IAM policy"),
    ("posturanet fix <sg-id> --dry-run", "see a fix, change nothing"),
    ("posturanet contract check --source", "check a change offline"),
)
_FROM, _TO = (0x31, 0x97, 0xF3), (0x00, 0x66, 0xFF)
_CI_VARS = ("CI", "GITHUB_ACTIONS", "BUILDKITE", "GITLAB_CI", "JENKINS_URL", "TF_BUILD")


def allowed(stream: TextIO) -> bool:
    """A person at a terminal, not a pipe, CI job or opt-out."""
    if os.environ.get("POSTURANET_NO_BANNER") or any(os.environ.get(v) for v in _CI_VARS):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _color_mode() -> str:
    if os.environ.get("NO_COLOR"):
        return "none"
    if os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit") or os.environ.get(
        "WT_SESSION"
    ):
        return "truecolor"
    return "256"


def _paint(line: str, row: int, rows: int, mode: str) -> str:
    if mode == "none":
        return line
    out = []
    for col, ch in enumerate(line):
        if ch == " ":
            out.append(ch)
            continue
        t = min(1.0, (col / WIDTH + row / rows) / 2)  # diagonal, like the SVG gradient
        if mode == "truecolor":
            r, g, b = (round(a + (z - a) * t) for a, z in zip(_FROM, _TO, strict=True))
            out.append(f"\x1b[38;2;{r};{g};{b}m{ch}")
        else:
            out.append(f"\x1b[38;5;{33 if t < 0.5 else 27}m{ch}")
    return "".join(out) + "\x1b[0m"


def render(*, ascii_mode: bool = False, color: str | None = None) -> str:
    """The banner text. `ascii_mode` drops the pixel logo (it needs Unicode blocks)."""
    if ascii_mode:
        lines = [f"PosturaNet {__version__}", TAGLINE, ""]
        lines += [f"-> {cmd:<36} {what}" for cmd, what in START]
        return "\n".join(lines) + "\n\n"
    mode = color or _color_mode()
    side = [
        "",
        "",
        "",
        f"PosturaNet {__version__}",
        TAGLINE,
        "",
        *(f"→ {cmd:<36} {what}" for cmd, what in START),
    ]
    rows = []
    for i, art in enumerate(LOGO):
        text = side[i] if i < len(side) else ""
        painted = _paint(art, i, len(LOGO), mode)
        rows.append((painted + " " * (WIDTH - len(art)) + "   " + text).rstrip())
    return "\n".join(rows) + "\n\n"
