"""Terminal colors for the design-system tokens (docs/04_DESIGN_SYSTEM.md section 10.3).

Only for a person at a terminal: off for pipes, `NO_COLOR`, `TERM=dumb`, JSON output and the
agent hooks. Every status keeps its word and symbol, so color is never the only signal.
"""

from __future__ import annotations

import contextlib
import importlib
import os
from typing import TextIO

_CODES = {
    "success": "32",  # green
    "critical": "31",  # red
    "warning": "33",  # yellow
    "muted": "2",  # dim
    "accent": "34",  # blue: links, next-step arrows
    "bold": "1",
}


def wants_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    isatty = getattr(stream, "isatty", None)
    if not (isatty and isatty()):
        return False
    _enable_windows_ansi()
    return True


def _enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    # colorama ships with typer on Windows; older consoles need it for ANSI
    with contextlib.suppress(ImportError, AttributeError):
        importlib.import_module("colorama").just_fix_windows_console()


class Style:
    """Wraps text in ANSI codes when enabled; a no-op otherwise."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, token: str, text: str) -> str:
        if not self.enabled or not text:
            return text
        return f"\x1b[{_CODES[token]}m{text}\x1b[0m"


PLAIN = Style(False)
