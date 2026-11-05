"""Read IAM policy documents in Terraform, with the text span of every `Action` (FR-51).

Three forms, edited in place:
- `policy = jsonencode({ ... })`: an HCL object literal.
- `policy = <<EOF ... EOF`: a JSON heredoc.
- `policy = data.aws_iam_policy_document.<name>.json`: `statement` blocks with `actions`.

A small tolerant parser for JSON and HCL object syntax. Anything it can't read as literals
(references, interpolation, `file()`, dynamic blocks, source/override documents) raises
`Unsupported` (NFR-1).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from posturanet.configfix.hcl_attrs import (
    Unsupported,
    _child,
    _NonLiteral,
    entries,
    parse_literal,
    resource_block,
)

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_NUM = re.compile(r"-?\d+(\.\d+)?([eE][+-]?\d+)?")
_DATA_REF = re.compile(r"^data\.aws_iam_policy_document\.([A-Za-z_][A-Za-z0-9_-]*)\.json$")
_HEREDOC = re.compile(r"<<(-?)([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n")


@dataclass
class Node:
    kind: Literal["obj", "list", "str", "lit", "expr"]
    start: int
    end: int
    value: Any = None
    items: list[tuple[str, Node]] = field(default_factory=list)
    elems: list[Node] = field(default_factory=list)

    def get(self, key: str) -> Node | None:
        return next((v for k, v in self.items if k == key), None)


class _Parser:
    def __init__(self, text: str, end: int) -> None:
        self.t, self.end = text, end

    def _line(self, i: int) -> int:
        return self.t.count("\n", 0, i) + 1

    def ws(self, i: int, commas: bool = False) -> int:
        t = self.t
        while i < self.end:
            ch = t[i]
            if ch in " \t\r\n" or (commas and ch == ","):
                i += 1
            elif ch == "#" or t.startswith("//", i):
                nl = t.find("\n", i)
                i = self.end if nl == -1 else nl
            elif t.startswith("/*", i):
                close = t.find("*/", i + 2)
                i = self.end if close == -1 else close + 2
            else:
                break
        return i

    def value(self, i: int) -> Node:
        i = self.ws(i)
        if i >= self.end:
            raise Unsupported("policy document ends early")
        ch = self.t[i]
        if ch == "{":
            return self._obj(i)
        if ch == "[":
            return self._list(i)
        if ch == '"':
            return self._str(i)
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.t.startswith(word, i) and not _IDENT.match(self.t, i + len(word)):
                return Node("lit", i, i + len(word), val)
        m = _NUM.match(self.t, i)
        if m:
            return Node("lit", i, m.end(), json.loads(m.group(0)))
        return self._expr(i)

    def _obj(self, i: int) -> Node:
        node = Node("obj", i, i)
        i += 1
        while True:
            i = self.ws(i, commas=True)
            if i >= self.end:
                raise Unsupported(f"unclosed object at line {self._line(node.start)}")
            if self.t[i] == "}":
                node.end = i + 1
                return node
            if self.t[i] == '"':
                key_node = self._str(i)
                if key_node.kind != "str":
                    raise Unsupported(f"computed key at line {self._line(i)}")
                key, i = str(key_node.value), key_node.end
            else:
                m = _IDENT.match(self.t, i)
                if not m:
                    raise Unsupported(f"unexpected syntax at line {self._line(i)}")
                key, i = m.group(0), m.end()
            i = self.ws(i)
            if i >= self.end or self.t[i] not in "=:":
                raise Unsupported(f"expected = or : at line {self._line(i)}")
            val = self.value(i + 1)
            node.items.append((key, val))
            i = val.end

    def _list(self, i: int) -> Node:
        node = Node("list", i, i)
        i += 1
        while True:
            i = self.ws(i, commas=True)
            if i >= self.end:
                raise Unsupported(f"unclosed list at line {self._line(node.start)}")
            if self.t[i] == "]":
                node.end = i + 1
                return node
            val = self.value(i)
            node.elems.append(val)
            i = val.end

    def _str(self, i: int) -> Node:
        t, j, interp = self.t, i + 1, False
        while j < self.end:
            ch = t[j]
            if ch == "\\":
                j += 2
                continue
            if t.startswith(("${", "%{"), j):
                interp = True
                depth, j = 1, j + 2
                while j < self.end and depth:
                    depth += {"{": 1, "}": -1}.get(t[j], 0)
                    j += 1
                continue
            if ch == '"':
                raw = t[i : j + 1]
                if interp:
                    return Node("expr", i, j + 1, raw)
                try:
                    return Node("str", i, j + 1, json.loads(raw))
                except json.JSONDecodeError:
                    return Node("expr", i, j + 1, raw)
            if ch == "\n":
                break
            j += 1
        raise Unsupported(f"unterminated string at line {self._line(i)}")

    def _expr(self, i: int) -> Node:
        t, j, depth = self.t, i, 0
        while j < self.end:
            ch = t[j]
            if ch == '"':
                j = self._str(j).end
                continue
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and ch in ",\n":
                break
            j += 1
        return Node("expr", i, j, t[i:j].strip())


# --- statements


@dataclass
class Statement:
    index: int
    sid: str | None
    effect: str
    actions: list[str] | None  # None: no Action (NotAction, or missing)
    not_action: bool
    resources: list[str]
    span: tuple[int, int] | None  # text span of the Action value
    indent: str  # indentation of the line holding the Action key
    container: tuple[int, int] = (0, 0)  # span of the statement object or block


@dataclass
class PolicyDoc:
    form: Literal["jsonencode", "heredoc", "policy_document"]
    file: Path
    text: str
    line: int  # line of the block that holds the statements
    statements: list[Statement]
    # `text` is always LF; the file on disk may be CRLF, and edits are written back that way.

    @property
    def original(self) -> str:
        return self.file.read_bytes().decode("utf-8")

    @property
    def crlf(self) -> bool:
        return "\r\n" in self.original


def _strs(node: Node | None, what: str) -> list[str] | None:
    if node is None:
        return None
    if node.kind == "str":
        return [str(node.value)]
    if node.kind == "list" and all(e.kind == "str" for e in node.elems):
        return [str(e.value) for e in node.elems]
    raise Unsupported(f"{what} is not a literal string or list; edit it by hand")


def _indent_at(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    m = re.match(r"[ \t]*", text[start:])
    return m.group(0) if m else ""


def _key_offset(text: str, value_start: int) -> int:
    """Start of the line that holds the key for a value."""
    return text.rfind("\n", 0, value_start) + 1


def statements_from_object(text: str, root: Node) -> list[Statement]:
    if root.kind != "obj":
        raise Unsupported("the policy is not an object literal")
    st = root.get("Statement")
    if st is None:
        raise Unsupported("the policy has no Statement")
    nodes = st.elems if st.kind == "list" else [st] if st.kind == "obj" else None
    if nodes is None:
        raise Unsupported("Statement is not a literal list")
    out = []
    for idx, s in enumerate(nodes):
        if s.kind != "obj":
            raise Unsupported(f"statement {idx + 1} is not a literal object")
        effect = s.get("Effect")
        if effect is None or effect.kind != "str":
            raise Unsupported(f"statement {idx + 1} has no literal Effect")
        action = s.get("Action")
        sid = s.get("Sid")
        resources = _strs(s.get("Resource"), "Resource") or []
        out.append(
            Statement(
                index=idx,
                sid=str(sid.value) if sid is not None and sid.kind == "str" else None,
                effect=str(effect.value),
                actions=_strs(action, "Action"),
                not_action=s.get("NotAction") is not None,
                resources=resources if s.get("NotResource") is None else ["<NotResource>"],
                span=(action.start, action.end) if action is not None else None,
                container=(s.start, s.end),
                indent=_indent_at(text, _key_offset(text, action.start)) if action else "",
            )
        )
    return out


def _policy_document(path: Path, text: str, line: int) -> list[Statement]:
    blk = resource_block(text, line)
    out: list[Statement] = []
    for e in entries(text, blk):
        if e.kind == "attr" and e.name in (
            "source_policy_documents",
            "override_policy_documents",
            "source_json",
            "override_json",
        ):
            raise Unsupported(f"the policy document merges {e.name}; edit it by hand")
        if e.kind == "block" and e.name == "dynamic":
            raise Unsupported("the policy document uses a dynamic statement; edit it by hand")
        if e.kind != "block" or e.name != "statement":
            continue
        sblk = _child(text, e)
        attrs = {a.name: a for a in entries(text, sblk) if a.kind == "attr"}

        def lit(name: str, sblk_text: str = text, attrs: dict[str, Any] = attrs) -> Any:
            a = attrs.get(name)
            if a is None:
                return None
            try:
                return parse_literal(sblk_text[a.value_start : a.end])
            except _NonLiteral as exc:
                raise Unsupported(f"{name} is not a literal; edit it by hand") from exc

        effect = lit("effect") or "Allow"
        actions = lit("actions")
        if actions is not None and not (
            isinstance(actions, list) and all(isinstance(a, str) for a in actions)
        ):
            raise Unsupported("actions is not a list of strings")
        resources = lit("resources") or []
        a = attrs.get("actions")
        out.append(
            Statement(
                index=len(out),
                sid=lit("sid"),
                effect=str(effect),
                actions=list(actions) if actions is not None else None,
                not_action="not_actions" in attrs,
                resources=[str(r) for r in resources]
                if "not_resources" not in attrs
                else ["<NotResource>"],
                span=(a.value_start, a.end) if a is not None else None,
                container=(sblk.open, sblk.end),
                indent=_indent_at(text, a.start) if a is not None else "",
            )
        )
    if not out:
        raise Unsupported("the policy document has no statement blocks")
    return out


def find_document(directory: Path, file: Path, line: int) -> PolicyDoc:
    """The policy document of the `aws_iam_policy` block at `file:line`."""
    text = file.read_bytes().decode("utf-8").replace("\r\n", "\n")
    blk = resource_block(text, line)
    body = text[blk.open + 1 : blk.end - 1]
    m = re.search(r"(?m)^[ \t]*policy[ \t]*=[ \t]*", body)
    if m is None:
        raise Unsupported("the aws_iam_policy has no policy argument")
    vs = blk.open + 1 + m.end()

    hd = _HEREDOC.match(text, vs)
    if hd:
        marker = hd.group(2)
        close = re.compile(rf"(?m)^[ \t]*{re.escape(marker)}[ \t]*$")
        cm = close.search(text, hd.end())
        if cm is None:
            raise Unsupported("unterminated heredoc in the policy")
        root = _Parser(text, cm.start()).value(hd.end())
        return PolicyDoc("heredoc", file, text, line, statements_from_object(text, root))

    if text.startswith("jsonencode(", vs):
        open_ = vs + len("jsonencode")
        close_ = _match_paren(text, open_)
        root = _Parser(text, close_).value(open_ + 1)
        if _Parser(text, close_).ws(root.end) != close_:
            raise Unsupported("jsonencode() holds more than one literal object")
        return PolicyDoc("jsonencode", file, text, line, statements_from_object(text, root))

    expr_end = text.find("\n", vs)
    expr = text[vs : expr_end if expr_end != -1 else len(text)].strip()
    ref = _DATA_REF.match(expr)
    if ref:
        name = ref.group(1)
        for tf in sorted(directory.glob("*.tf")):
            t = tf.read_bytes().decode("utf-8").replace("\r\n", "\n")
            header = rf'(?m)^[ \t]*data[ \t]+"aws_iam_policy_document"[ \t]+"{re.escape(name)}"'
            dm = re.search(header + r"[ \t]*\{", t)
            if dm:
                dline = t.count("\n", 0, dm.start()) + 1
                return PolicyDoc("policy_document", tf, t, dline, _policy_document(tf, t, dline))
        raise Unsupported(f'data "aws_iam_policy_document" "{name}" not found in this module')
    raise Unsupported(f"policy = {expr[:40]} isn't a literal document PosturaNet can edit")


def _match_paren(text: str, open_: int) -> int:
    depth, i, n = 0, open_, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i = _Parser(text, n)._str(i).end
            continue
        if ch == "#" or text.startswith("//", i):
            nl = text.find("\n", i)
            i = n if nl == -1 else nl
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise Unsupported("unclosed jsonencode(")


def render_actions(actions: list[str], indent: str, *, multiline: bool) -> str:
    """A list literal valid in JSON and HCL."""
    if not multiline or len(actions) == 1:
        return "[" + ", ".join(json.dumps(a) for a in actions) + "]"
    inner = ",\n".join(f"{indent}  {json.dumps(a)}" for a in actions)
    return f"[\n{inner}\n{indent}]"


_ATTR_LINE = re.compile(r"^([ \t]*)([A-Za-z_][A-Za-z0-9_-]*)[ \t]*=[ \t]*(.*)$")


def _balanced(value: str) -> bool:
    depth, in_str, i = 0, False, 0
    while i < len(value):
        ch = value[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "#" or value.startswith("//", i):
            break
        i += 1
    return depth == 0 and not in_str and "<<" not in value


def realign(text: str, start: int, end: int, indent: str) -> str:
    """Align `=` the way `terraform fmt` does, for attribute lines at `indent` in [start, end).

    A group is a run of consecutive single-line attributes; any other line (blank, comment,
    block, deeper line, or an attribute whose value spans lines) ends it. Multi-line
    attributes get a single space before `=`.
    """
    line_start = text.rfind("\n", 0, start) + 1
    region = text[line_start:end]
    lines = region.split("\n")
    out = list(lines)
    group: list[tuple[int, str, str]] = []

    def flush() -> None:
        width = max((len(k) for _, k, _ in group), default=0)
        for idx, key, value in group:
            out[idx] = f"{indent}{key.ljust(width)} = {value}"
        group.clear()

    for idx, line in enumerate(lines):
        m = _ATTR_LINE.match(line)
        if m and m.group(1) == indent:
            if _balanced(m.group(3)):
                group.append((idx, m.group(2), m.group(3)))
                continue
            flush()
            out[idx] = f"{indent}{m.group(2)} = {m.group(3)}"
            continue
        flush()
    flush()
    return text[:line_start] + "\n".join(out) + text[end:]


def statements_from_json(policy: str) -> list[dict[str, Any]]:
    """Statements of a policy JSON string (plan/state), normalized to lists."""
    doc = json.loads(policy)
    st = doc.get("Statement", [])
    nodes = st if isinstance(st, list) else [st]
    out = []
    for s in nodes:
        if not isinstance(s, dict):
            continue
        norm = dict(s)
        for k in ("Action", "NotAction", "Resource", "NotResource"):
            if isinstance(norm.get(k), str):
                norm[k] = [norm[k]]
        out.append(norm)
    return out


def reparse(doc: PolicyDoc, text: str) -> list[Statement]:
    """Statements of `doc` read again from edited text (same file, same block line)."""
    if doc.form == "policy_document":
        return _policy_document(doc.file, text, doc.line)
    blk = resource_block(text, doc.line)
    body = text[blk.open + 1 : blk.end - 1]
    m = re.search(r"(?m)^[ 	]*policy[ 	]*=[ 	]*", body)
    if m is None:
        raise Unsupported("the aws_iam_policy has no policy argument")
    vs = blk.open + 1 + m.end()
    if doc.form == "heredoc":
        hd = _HEREDOC.match(text, vs)
        assert hd is not None
        close = re.compile(rf"(?m)^[ 	]*{re.escape(hd.group(2))}[ 	]*$")
        cm = close.search(text, hd.end())
        if cm is None:
            raise Unsupported("unterminated heredoc in the policy")
        return statements_from_object(text, _Parser(text, cm.start()).value(hd.end()))
    open_ = vs + len("jsonencode")
    close_ = _match_paren(text, open_)
    return statements_from_object(text, _Parser(text, close_).value(open_ + 1))


__all__ = [
    "Node",
    "PolicyDoc",
    "Statement",
    "find_document",
    "reparse",
    "render_actions",
    "statements_from_json",
    "statements_from_object",
]
