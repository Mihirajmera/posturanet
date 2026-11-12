"""The rail and boxes that frame CLI text output (docs/04_DESIGN_SYSTEM.md section 4.1).

    ┌  PosturaNet 0.2.0 · fix · sg-0a91f3c2      open
    │
    ◇  ✓ ingest      …                           a step
    │                                            the rail
    ◇  Result ──────────╮                        a box
    │  DRY RUN · …      │
    ├───────────────────╯
    │
    └  Done. Nothing was changed.                close

ASCII mode swaps every glyph for `+ | o * -`. A box wider than `width` drops its right
edge instead of wrapping. Pure text in, text out: color comes from the `Style` passed in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from posturanet.output.style import PLAIN, Style
from posturanet.output.symbols import to_ascii

_UNICODE = {"top": "┌", "bar": "│", "step": "◇", "info": "●", "end": "└", "h": "─"}
_UNICODE |= {"tr": "╮", "br": "╯", "tee": "├"}
_ASCII = {"top": "+", "bar": "|", "step": "o", "info": "*", "end": "+", "h": "-"}
_ASCII |= {"tr": "+", "br": "+", "tee": "+"}
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
GAP = "  "


def visible_len(text: str) -> int:
    return len(_ANSI.sub("", text))


@dataclass
class Frame:
    ascii_mode: bool = False
    style: Style = PLAIN
    width: int | None = None  # terminal columns; None means no limit

    def _g(self, name: str) -> str:
        return (_ASCII if self.ascii_mode else _UNICODE)[name]

    def _rail(self, name: str) -> str:
        return self.style("muted", self._g(name))

    def open(self, title: str) -> list[str]:
        return [f"{self._rail('top')}{GAP}{title}", self._rail("bar")]

    def step(self, text: str, *, info: bool = False, token: str = "muted") -> str:
        node = self.style(token, self._g("info" if info else "step"))
        return f"{node}{GAP}{text}"

    def bar(self, text: str = "") -> str:
        return f"{self._rail('bar')}{GAP}{text}" if text else self._rail("bar")

    def close(self, text: str) -> list[str]:
        return [f"{self._rail('end')}{GAP}{text}"]

    def box(self, title: str, rows: list[str], *, token: str = "muted") -> list[str]:
        """`◇  Title ───╮`, the rows between `│ … │`, then `├───╯` and a rail line."""
        if self.ascii_mode:  # measure the text as it will print
            title, rows = to_ascii(title), [to_ascii(r) for r in rows]
        inner = max([visible_len(title), *(visible_len(r) for r in rows)])
        h, bar = self._g("h"), self._rail("bar")
        closed = self.width is None or inner + 6 <= self.width
        if not closed:
            top = self.step(self.style("bold", title), token=token)
            body = [f"{bar}{GAP}{r}" if r else bar for r in rows]
            return [top, *body, bar]
        rule = self.style("muted", h * (inner + 1 - visible_len(title)) + self._g("tr"))
        top = self.step(f"{self.style('bold', title)} {rule}", token=token)
        padded = ["", *rows, ""]
        body = [f"{bar}{GAP}{r}{' ' * (inner - visible_len(r))}{GAP}{bar}" for r in padded]
        bottom = self.style("muted", self._g("tee") + h * (inner + 4) + self._g("br"))
        return [top, *body, bottom, bar]
