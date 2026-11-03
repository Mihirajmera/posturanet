"""Read and edit literal attributes inside one HCL resource block (FR-48).

A small scanner, not a full HCL parser. It edits only what it fully understands (literal
values in static blocks) and raises `Unsupported` for anything else: variables, expressions,
`dynamic` blocks, repeated blocks, heredocs (NFR-1).

New attributes go in as their own group after a blank line, aligned the way `terraform fmt`
aligns them, so a fmt-clean file stays fmt-clean.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

from posturanet.configfix.catalog import PRESENT, Change, Condition
from posturanet.locate.hcl_index import block_span, offset_of_line

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_INT = re.compile(r"-?\d+")
_CLOSE = {"(": ")", "[": "]", "{": "}"}


class Unsupported(Exception):
    """The code is outside what PosturaNet edits safely. The message says why."""


class _Absent:
    def __repr__(self) -> str:
        return "ABSENT"


class _Block:
    def __repr__(self) -> str:
        return "BLOCK"


ABSENT = _Absent()
BLOCK = _Block()
Value = bool | int | str | list[object] | None


@dataclass(frozen=True)
class Entry:
    kind: Literal["attr", "block"]
    name: str
    labels: tuple[str, ...]
    start: int
    end: int  # attr: end of the value text; block: one past the closing brace
    value_start: int  # attr: start of the value; block: offset of "{"


@dataclass(frozen=True)
class Block:
    open: int  # offset of "{"
    end: int  # one past "}"
    indent: str


# --- scanning


def resource_block(text: str, line: int) -> Block:
    start = offset_of_line(text, line)
    open_, end = block_span(text, start)
    if end > len(text) or text[end - 1] != "}":
        raise Unsupported(f"the block at line {line} is not closed")
    return Block(open_, end, _indent(text, start))


def _indent(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    m = re.match(r"[ \t]*", text[line_start:])
    return m.group(0) if m else ""


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _skip_trivia(text: str, i: int, end: int) -> int:
    while i < end:
        ch = text[i]
        if ch in " \t\r\n":
            i += 1
        elif ch == "#" or text.startswith("//", i):
            nl = text.find("\n", i)
            i = end if nl == -1 or nl > end else nl
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            if close == -1:
                raise Unsupported(f"unterminated comment at line {_line_of(text, i)}")
            i = close + 2
        else:
            break
    return i


def _expr_end(text: str, i: int, end: int) -> int:
    """End of the expression at `i`: the first newline outside brackets, strings and templates."""
    stack: list[str] = []
    while i < end:
        ch = text[i]
        if stack and stack[-1] == '"':
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                stack.pop()
            elif text.startswith(("${", "%{"), i):
                stack.append("}")
                i += 2
                continue
            i += 1
            continue
        if ch == '"':
            stack.append('"')
        elif text.startswith("<<", i):
            raise Unsupported(f"heredoc at line {_line_of(text, i)} is not edited")
        elif ch == "#" or text.startswith("//", i):
            if not stack:
                return i
            nl = text.find("\n", i)
            i = end if nl == -1 else nl
            continue
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = end if close == -1 else close + 2
            continue
        elif ch in _CLOSE:
            stack.append(_CLOSE[ch])
        elif ch in ")]}":
            if not stack:
                return i
            stack.pop()
        elif ch == "\n" and not stack:
            return i
        i += 1
    return i


def entries(text: str, blk: Block) -> list[Entry]:
    i, end = blk.open + 1, blk.end - 1
    out: list[Entry] = []
    while True:
        i = _skip_trivia(text, i, end)
        if i >= end:
            return out
        m = _IDENT.match(text, i)
        if not m:
            raise Unsupported(f"unexpected syntax at line {_line_of(text, i)}")
        name, j = m.group(0), m.end()
        while j < end and text[j] in " \t":
            j += 1
        if text.startswith("=", j) and not text.startswith("==", j):
            vs = j + 1
            while vs < end and text[vs] in " \t":
                vs += 1
            ve = _expr_end(text, vs, end)
            raw_end = vs + len(text[vs:ve].rstrip())
            out.append(Entry("attr", name, (), i, raw_end, vs))
            i = ve
            continue
        labels: list[str] = []
        while j < end and text[j] == '"':
            k = text.find('"', j + 1)
            if k == -1:
                raise Unsupported(f"unterminated label at line {_line_of(text, j)}")
            labels.append(text[j + 1 : k])
            j = k + 1
            while j < end and text[j] in " \t":
                j += 1
        if j >= end or text[j] != "{":
            raise Unsupported(f"unexpected syntax at line {_line_of(text, i)}")
        _, bend = block_span(text, j)
        out.append(Entry("block", name, tuple(labels), i, bend, j))
        i = bend


def _child(text: str, entry: Entry) -> Block:
    return Block(entry.value_start, entry.end, _indent(text, entry.start))


def _find(text: str, blk: Block, name: str) -> Entry | None:
    """The one attribute or static block called `name`, None if absent; Unsupported otherwise."""
    found = []
    for e in entries(text, blk):
        if e.kind == "block" and e.name == "dynamic" and e.labels[:1] == (name,):
            raise Unsupported(f'"{name}" is a dynamic block; edit it by hand')
        if e.name == name:
            found.append(e)
    if len(found) > 1:
        kinds = "blocks" if found[0].kind == "block" else "attributes"
        raise Unsupported(f'{len(found)} "{name}" {kinds}; PosturaNet edits only one')
    return found[0] if found else None


def _navigate(text: str, blk: Block, parents: list[str]) -> tuple[Block, list[str]]:
    """Deepest existing block along `parents`, and the names still missing below it."""
    for idx, name in enumerate(parents):
        e = _find(text, blk, name)
        if e is None:
            return blk, parents[idx:]
        if e.kind == "attr":
            raise Unsupported(f'"{name}" is set as an attribute (object syntax); edit it by hand')
        blk = _child(text, e)
    return blk, []


# --- literals


class _NonLiteral(Exception):
    pass


def parse_literal(src: str) -> Value:
    src = src.strip()
    if src in ("true", "false"):
        return src == "true"
    if src == "null":
        return None
    if _INT.fullmatch(src):
        return int(src)
    if src.startswith('"'):
        return _string(src)
    if src.startswith("[") and src.endswith("]"):
        inner = src[1:-1]
        if "#" in inner or "//" in inner or "/*" in inner:
            raise _NonLiteral
        items = [part.strip() for part in _split_commas(inner)]
        values: list[object] = []
        for item in items:
            if not item:
                continue
            v = parse_literal(item)
            if isinstance(v, list):
                raise _NonLiteral
            values.append(v)
        return values
    raise _NonLiteral


def _string(src: str) -> str:
    if len(src) < 2 or not src.endswith('"') or "${" in src or "%{" in src:
        raise _NonLiteral
    try:
        value = json.loads(src)
    except json.JSONDecodeError as exc:
        raise _NonLiteral from exc
    if not isinstance(value, str):
        raise _NonLiteral
    return value


def _split_commas(inner: str) -> list[str]:
    parts, buf, in_str, i = [], [], False, 0
    while i < len(inner):
        ch = inner[i]
        if in_str and ch == "\\":
            buf.append(inner[i : i + 2])
            i += 2
            continue
        if ch == '"':
            in_str = not in_str
        if ch == "," and not in_str:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def render(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(render(v) for v in value) + "]"
    return json.dumps(value)


def _coerce(current: Value, like: object) -> Value:
    """Terraform accepts "true" and "7" for bool and number arguments; compare them as such."""
    if isinstance(current, str) and isinstance(like, bool) and current in ("true", "false"):
        return current == "true"
    if isinstance(current, str) and isinstance(like, int) and _INT.fullmatch(current):
        return int(current)
    return current


# --- reading


def lookup(text: str, line: int, path: str) -> Value | _Absent | _Block:
    """Value at `path` in the resource at `line`: a literal, ABSENT, or BLOCK."""
    text = text.replace("\r\n", "\n")
    *parents, name = path.split(".")
    blk, missing = _navigate(text, resource_block(text, line), parents)
    if missing:
        return ABSENT
    e = _find(text, blk, name)
    if e is None:
        return ABSENT
    if e.kind == "block":
        return BLOCK
    try:
        return parse_literal(text[e.value_start : e.end])
    except _NonLiteral as exc:
        raise Unsupported(f"{path} is not a literal value ({text[e.value_start : e.end]})") from exc


def applies(text: str, line: int, conditions: list[Condition]) -> tuple[bool, str]:
    for cond in conditions:
        value = lookup(text, line, cond.path)
        if value is ABSENT:
            ok = None in cond.in_
            shown = "absent"
        elif value is BLOCK:
            ok = PRESENT in cond.in_
            shown = "present"
        else:
            ok = PRESENT in cond.in_ or (value is not None and str(value) in cond.in_)
            shown = render(value)
        if not ok:
            wanted = ", ".join("absent" if v is None else v for v in cond.in_)
            return False, f"{cond.path} is {shown}; this fix applies when it is {wanted}"
    return True, ""


def satisfied(text: str, line: int, change: Change) -> bool:
    value = lookup(text, line, change.path)
    if value is ABSENT or value is BLOCK:
        return False
    return change.satisfied_by(_coerce(value, change.value))  # type: ignore[arg-type]


# --- editing


@dataclass
class EditResult:
    text: str
    changed: list[str]  # descriptions of changes made
    already: list[str]  # changes the code already satisfied


def apply_changes(text: str, line: int, changes: list[Change]) -> EditResult:
    crlf = "\r\n" in text
    text = text.replace("\r\n", "\n")
    _check_ignore_changes(text, line, changes)

    changed: list[str] = []
    already: list[str] = []
    pending: dict[tuple[str, ...], list[tuple[str, object]]] = {}
    for c in changes:
        blk, missing = _navigate(text, resource_block(text, line), c.parents)
        e = None if missing else _find(text, blk, c.name)
        if e is None:
            pending.setdefault(tuple(c.parents), []).append((c.name, c.value))
            changed.append(c.describe())
            continue
        if e.kind == "block":
            raise Unsupported(f'"{c.path}" is a block, not an attribute')
        raw = text[e.value_start : e.end]
        try:
            current = _coerce(parse_literal(raw), c.value)
        except _NonLiteral as exc:
            raise Unsupported(f"{c.path} is set to an expression ({raw}); edit it by hand") from exc
        if c.satisfied_by(current):
            already.append(c.describe())
            continue
        new_value: object = c.value
        if c.op == "includes":
            have = current if isinstance(current, list) else []
            new_value = [*have, *(v for v in c.value if v not in have)]  # type: ignore[union-attr]
        text = text[: e.value_start] + render(new_value) + text[e.end :]
        changed.append(c.describe())

    for parents, attrs in pending.items():
        blk, missing = _navigate(text, resource_block(text, line), list(parents))
        text = _insert(text, blk, _nested(missing, attrs))

    if crlf:
        text = text.replace("\n", "\r\n")
    return EditResult(text, changed, already)


def _check_ignore_changes(text: str, line: int, changes: list[Change]) -> None:
    blk = resource_block(text, line)
    lifecycle = _find(text, blk, "lifecycle")
    if lifecycle is None or lifecycle.kind != "block":
        return
    ignore = _find(text, _child(text, lifecycle), "ignore_changes")
    if ignore is None:
        return
    raw = text[ignore.value_start : ignore.end]
    if raw.strip() == "all":
        raise Unsupported("lifecycle.ignore_changes = all; Terraform would never apply the fix")
    for c in changes:
        top = c.path.split(".", 1)[0]
        if re.search(rf"(?<![\w-]){re.escape(top)}(?![\w-])", raw):
            raise Unsupported(
                f"lifecycle.ignore_changes covers {top}; Terraform would never apply the fix"
            )


def _nested(missing: list[str], attrs: list[tuple[str, object]]) -> list[str]:
    width = max(len(name) for name, _ in attrs)
    lines = [f"{name.ljust(width)} = {render(value)}" for name, value in attrs]
    for name in reversed(missing):
        lines = [f"{name} {{", *(f"  {ln}" for ln in lines), "}"]
    return lines


def _insert(text: str, blk: Block, lines: list[str]) -> str:
    child = blk.indent + "  "
    close = blk.end - 1
    body = text[blk.open + 1 : close]
    block_text = "".join(f"{child}{ln}\n" for ln in lines)
    if not body.strip():
        return text[: blk.open + 1] + "\n" + block_text + blk.indent + text[close:]
    line_start = text.rfind("\n", 0, close) + 1
    if text[line_start:close].strip():
        raise Unsupported(
            f"the block closing at line {_line_of(text, close)} shares a line with content"
        )
    gap = "" if text[:line_start].endswith("\n\n") else "\n"
    return text[:line_start] + gap + block_text + text[line_start:]
