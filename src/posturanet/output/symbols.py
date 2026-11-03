"""Status symbols from docs/04_DESIGN_SYSTEM.md, with ASCII fallbacks."""

from __future__ import annotations

from posturanet.models import StageStatus

UNICODE = {
    StageStatus.OK: "✓",
    StageStatus.FAIL: "✗",
    StageStatus.WARN: "!",
    StageStatus.UNKNOWN: "?",
    StageStatus.SKIPPED: "–",
}
ASCII = {
    StageStatus.OK: "[ok]",
    StageStatus.FAIL: "[x]",
    StageStatus.WARN: "[!]",
    StageStatus.UNKNOWN: "[?]",
    StageStatus.SKIPPED: "[-]",
}
BULLET = {"unicode": "•", "ascii": "-"}

_ASCII_REPLACEMENTS = {"·": "-", "→": "->", "•": "-", "–": "-", "✓": "[ok]", "✗": "[x]", "…": "..."}


def to_ascii(text: str) -> str:
    for src, dst in _ASCII_REPLACEMENTS.items():
        text = text.replace(src, dst)
    return text
