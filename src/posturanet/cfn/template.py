"""CloudFormation and SAM templates (YAML or JSON) as nodes with exact source spans.

Templates are composed, not loaded: every node keeps its start and end offset in the text, so
an edit replaces only the characters it must and the rest of the file stays byte-for-byte the
customer's. Short-form intrinsics (`!Ref`, `!GetAtt`, `!Sub` …) read as their long forms.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

_SKIP_DIRS = {".git", "node_modules", "cdk.out", ".aws-sam", ".posturanet", ".venv", ".terraform"}
_SUFFIXES = {".yaml", ".yml", ".json", ".template"}
_INT = "tag:yaml.org,2002:int"
_BOOL = "tag:yaml.org,2002:bool"
_NULL = "tag:yaml.org,2002:null"
_FLOAT = "tag:yaml.org,2002:float"


class TemplateError(Exception):
    """The file isn't a template PosturaNet can read."""


@dataclass
class Template:
    path: Path
    text: str  # LF line endings; `crlf` says how to write it back
    crlf: bool
    root: MappingNode
    is_json: bool

    @property
    def resources(self) -> dict[str, MappingNode]:
        res = get(self.root, "Resources")
        if not isinstance(res, MappingNode):
            return {}
        return {k.value: v for k, v in res.value if isinstance(v, MappingNode)}

    @property
    def sam(self) -> bool:
        transform = value(get(self.root, "Transform"))
        names = transform if isinstance(transform, list) else [transform]
        return any(isinstance(n, str) and n.startswith("AWS::Serverless") for n in names)

    def on_disk(self, text: str) -> str:
        return text.replace("\n", "\r\n") if self.crlf else text


def parse(text: str, path: Path) -> Template:
    lf = text.replace("\r\n", "\n")
    try:
        root = YAML().compose(lf)
    except YAMLError as exc:
        raise TemplateError(f"{path.name} is not valid YAML or JSON") from exc
    if not isinstance(root, MappingNode) or not isinstance(get(root, "Resources"), MappingNode):
        raise TemplateError(f"{path.name} has no Resources section")
    return Template(path, lf, "\r\n" in text, root, bool(root.flow_style))


def load(path: Path) -> Template:
    return parse(path.read_bytes().decode("utf-8"), path)


def maybe_template(path: Path) -> str | None:
    """The file's text if it may be a template (suffix and a cheap content sniff), else None."""
    if path.suffix.lower() not in _SUFFIXES or not path.is_file():
        return None
    text = path.read_bytes().decode("utf-8", errors="replace")
    return text if "AWS::" in text and "Resources" in text else None


def find_templates(root: Path) -> list[Template]:
    """Every CloudFormation or SAM template under `root`, sorted by path."""
    out: list[Template] = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() not in _SUFFIXES:
            continue
        if _SKIP_DIRS & set(p.relative_to(root).parts[:-1]):
            continue
        text = maybe_template(p)
        if text is None:
            continue
        try:
            t = parse(text, p)
        except TemplateError:
            continue
        if any(str(value(get(r, "Type"))).startswith("AWS::") for r in t.resources.values()):
            out.append(t)
    return out


# --- nodes


def get(node: Node | None, key: str) -> Node | None:
    if not isinstance(node, MappingNode):
        return None
    for k, v in node.value:
        if isinstance(k, ScalarNode) and k.value == key:
            return v  # type: ignore[no-any-return]
    return None


def key_node(node: MappingNode, key: str) -> ScalarNode | None:
    for k, _ in node.value:
        if isinstance(k, ScalarNode) and k.value == key:
            return k
    return None


def _scalar(node: ScalarNode) -> Any:
    tag, text = str(node.tag), node.value
    if tag == _INT:
        return int(text, 0)
    if tag == _BOOL:
        return text.lower() == "true"
    if tag == _NULL:
        return None
    if tag == _FLOAT:
        return float(text)
    return text


def value(node: Node | None) -> Any:
    """Plain Python value; short-form intrinsics become their long form."""
    if node is None:
        return None
    if isinstance(node, MappingNode):
        out: Any = {str(k.value): value(v) for k, v in node.value}
    elif isinstance(node, SequenceNode):
        out = [value(v) for v in node.value]
    else:
        assert isinstance(node, ScalarNode)
        out = _scalar(node)
    tag = str(node.tag)
    if not tag.startswith("!"):
        return out
    name = tag[1:]
    if name == "Ref":
        return {"Ref": out}
    if name == "GetAtt" and isinstance(out, str):
        return {"Fn::GetAtt": out.split(".", 1)}
    return {f"Fn::{name}": out}


def is_intrinsic(v: Any) -> bool:
    if not isinstance(v, dict) or len(v) != 1:
        return False
    key = str(next(iter(v)))
    return key in ("Ref", "Condition") or key.startswith("Fn::")


def start(node: Node) -> int:
    return int(node.start_mark.index)


def end(node: Node) -> int:
    """One past the node's last character. Block collections end at their last child, so
    trailing comments and blank lines stay outside the span."""
    if isinstance(node, MappingNode) and not node.flow_style and node.value:
        return end(node.value[-1][1])
    if isinstance(node, SequenceNode) and not node.flow_style and node.value:
        return end(node.value[-1])
    return int(node.end_mark.index)


def line_of(node: Node) -> int:
    return int(node.start_mark.line) + 1


def line_start(text: str, pos: int) -> int:
    return text.rfind("\n", 0, pos) + 1


def line_end(text: str, pos: int) -> int:
    """Offset just past the newline that ends the line holding `pos`."""
    nl = text.find("\n", pos)
    return len(text) if nl < 0 else nl + 1


def indent_of(text: str, pos: int) -> str:
    m = re.match(r"[ \t]*", text[line_start(text, pos) :])
    return m.group(0) if m else ""


# --- rendering


_PLAIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_:./*\- ]*[A-Za-z0-9_./*\-])?")


def scalar_text(v: Any, *, as_json: bool) -> str:
    if isinstance(v, list):  # a list of scalars, as a flow sequence
        return "[" + ", ".join(scalar_text(x, as_json=as_json) for x in v) + "]"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    s = str(v)
    reserved = s.lower() in ("true", "false", "null", "yes", "no")
    if as_json or reserved or ": " in s or not _PLAIN.fullmatch(s):
        return json.dumps(s)
    return s


def block_mapping(pairs: list[tuple[str, Any]], indent: str, step: str) -> list[str]:
    """Block-YAML lines for `pairs` (values: scalars, lists of scalars or nested pairs)."""
    lines: list[str] = []
    for k, v in pairs:
        if isinstance(v, list) and v and isinstance(v[0], tuple):
            lines.append(f"{indent}{k}:")
            lines += block_mapping(v, indent + step, step)
        else:
            lines.append(f"{indent}{k}: {scalar_text(v, as_json=False)}")
    return lines


def json_mapping(pairs: list[tuple[str, Any]], indent: str, step: str, *, multiline: bool) -> str:
    """A JSON object for `pairs`. `indent` is the indentation of the line it closes on."""
    items = []
    for k, v in pairs:
        if isinstance(v, list) and v and isinstance(v[0], tuple):
            rendered = json_mapping(v, indent + step, step, multiline=multiline)
        else:
            rendered = scalar_text(v, as_json=True)
        items.append(f"{json.dumps(k)}: {rendered}")
    if not multiline:
        return "{" + ", ".join(items) + "}"
    inner = indent + step
    return "{\n" + ",\n".join(inner + i for i in items) + "\n" + indent + "}"
