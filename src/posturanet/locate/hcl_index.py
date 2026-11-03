"""Minimal HCL index: find `resource` and `module` blocks with line numbers (FR-7).

R0 uses a small scanner instead of a full HCL parser. It only needs block headers and the
`source` attribute of module blocks. python-hcl2 replaces this when attribute parsing is needed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_RESOURCE_HEADER = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
_MODULE_HEADER = re.compile(r'^\s*module\s+"([^"]+)"\s*\{')
_SOURCE_ATTR = re.compile(r'^\s*source\s*=\s*"([^"]+)"', re.MULTILINE)


@dataclass(frozen=True)
class BlockRef:
    file: Path
    line: int  # 1-based


def find_resource_block(directory: Path, rtype: str, name: str) -> BlockRef | None:
    for tf in _tf_files(directory):
        for lineno, line in enumerate(tf.read_text(encoding="utf-8").splitlines(), start=1):
            m = _RESOURCE_HEADER.match(line)
            if m and m.group(1) == rtype and m.group(2) == name:
                return BlockRef(tf, lineno)
    return None


def find_module_source(directory: Path, module_name: str) -> tuple[str, BlockRef] | None:
    for tf in _tf_files(directory):
        text = tf.read_text(encoding="utf-8")
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            m = _MODULE_HEADER.match(line)
            if not m or m.group(1) != module_name:
                continue
            body = _block_body(text, _offset_of_line(lines, idx))
            src = _SOURCE_ATTR.search(body)
            if src:
                return src.group(1), BlockRef(tf, idx + 1)
    return None


def is_local_source(source: str) -> bool:
    return source.startswith(("./", "../"))


def _tf_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.glob("*.tf") if p.is_file())


def _offset_of_line(lines: list[str], idx: int) -> int:
    return sum(len(line) + 1 for line in lines[:idx])


def _block_body(text: str, start: int) -> str:
    i, j = block_span(text, start)
    return text[i:j]


def block_span(text: str, start: int) -> tuple[int, int]:
    """(open_brace, end) of the block whose header starts at `start`; honors strings/comments.

    `end` is one past the closing brace, or len(text) if the block is unterminated.
    """
    i = text.index("{", start)
    depth, j, n = 0, i, len(text)
    in_str = False
    while j < n:
        ch = text[j]
        if in_str:
            if ch == "\\":
                j += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "#" or text.startswith("//", j):
            nl = text.find("\n", j)
            j = n if nl == -1 else nl
            continue
        elif text.startswith("/*", j):
            end = text.find("*/", j + 2)
            j = n if end == -1 else end + 2
            continue
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i, j + 1
        j += 1
    return i, n


def offset_of_line(text: str, line: int) -> int:
    """Character offset of the start of 1-based `line`."""
    return sum(len(chunk) for chunk in text.splitlines(keepends=True)[: line - 1])
