"""Pulumi YAML programs (`runtime: yaml`): find a resource by its logical name in the
`resources:` map and read or edit its literal properties.

The file is read with ruamel.yaml's parser, which gives the exact position of every value, so
an edit replaces only the characters of the values it changes: comments, key order, quotes and
indentation stay. Strings, integers, booleans, lists and maps are literals, and `fn::toJSON` of
a literal map reads like `JSON.stringify`. An interpolation (`${…}`, which is also how
variables and config are read), any other `fn::` call, an anchor, alias or tag, a merge key and
every other scalar (null, float, date) read as COMPUTED.
"""

from __future__ import annotations

import io
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.events import (
    AliasEvent,
    Event,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from ruamel.yaml.nodes import ScalarNode
from ruamel.yaml.resolver import VersionedResolver

from posturanet.cdk.source import BY_HAND, Construct, line_end, line_start, unsupported
from posturanet.errors import StageStop
from posturanet.pulumi.source import Lit, Props

_RESOLVER = VersionedResolver(version=(1, 2))
_NO = object()  # a scalar that is not a str, int or bool literal
_ITEM = re.compile(r"[ \t]*-[ \t]+")  # what precedes an item of a block list on its line


@dataclass
class Node:
    kind: str  # scalar | seq | map | other (an alias, or a node with an anchor or tag)
    start: int
    end: int
    flow: bool = False
    style: str = ""  # scalar: "", '"', "'", "|" or ">"
    value: Any = None  # scalar: its text; seq: list[Node]; map: list[tuple[Node, Node]]

    def get(self, key: str) -> Node | None:
        if self.kind != "map":
            return None
        return next((v for k, v in self.value if k.kind == "scalar" and k.value == key), None)


def _node(ev: Any, events: Iterator[Event]) -> Node:
    s = ev.start_mark.index
    if isinstance(ev, AliasEvent):
        return Node("other", s, ev.end_mark.index)
    marked = ev.anchor is not None or ev.tag is not None
    if isinstance(ev, ScalarEvent):
        style = ev.style or ""
        return Node("other" if marked else "scalar", s, ev.end_mark.index, style=style,
                    value=ev.value)  # fmt: skip
    flow = bool(ev.flow_style)
    nxt = next(events)
    if isinstance(ev, SequenceStartEvent):
        items = []
        while not isinstance(nxt, SequenceEndEvent):
            items.append(_node(nxt, events))
            nxt = next(events)
        end = nxt.end_mark.index if flow else items[-1].end if items else s
        n = Node("seq", s, end, flow, value=items)
    else:
        pairs = []
        while not isinstance(nxt, MappingEndEvent):
            k = _node(nxt, events)
            pairs.append((k, _node(next(events), events)))
            nxt = next(events)
        end = nxt.end_mark.index if flow else pairs[-1][1].end if pairs else s
        n = Node("map", s, end, flow, value=pairs)
    return Node("other", s, n.end) if marked else n


def _stop(why: str) -> StageStop:
    return StageStop("locate", why, [BY_HAND], unknown=True)


def tree(text: str, name: str) -> Node:
    """The one document in `text` (LF line endings)."""
    docs = []
    try:
        events = iter(YAML().parse(io.StringIO(text)))
        for ev in events:
            if isinstance(ev, (ScalarEvent, AliasEvent, SequenceStartEvent, MappingStartEvent)):
                docs.append(_node(ev, events))
    except YAMLError as exc:
        raise _stop(f"{name} is not YAML PosturaNet can read ({type(exc).__name__})") from exc
    if len(docs) != 1:
        raise _stop(f"{name} has {len(docs)} YAML documents; a Pulumi program has one")
    return docs[0]


def scalar(n: Node) -> Any:
    """A scalar's str, int or bool value; `_NO` for anything else."""
    if n.kind != "scalar":
        return _NO
    if n.style:  # quoted or block: always a string
        return n.value
    tag = str(_RESOLVER.resolve(ScalarNode, n.value, (True, False)))
    if tag.endswith(":str"):
        return n.value
    if tag.endswith(":bool"):
        return n.value.lower() == "true"
    if tag.endswith(":int") and re.fullmatch(r"[-+]?\d+", n.value):
        return int(n.value)
    return _NO


def lit(text: str, n: Node) -> Lit:
    span = (n.start, n.end)
    computed = Lit(span, "computed", text[n.start : n.end])
    if n.kind == "scalar":
        v = scalar(n)
        if v is _NO or (isinstance(v, str) and "${" in v):
            return computed
        if isinstance(v, bool):
            return Lit(span, "bool", v)
        if isinstance(v, int):
            return Lit(span, "num", v)
        return Lit(span, "str", v, n.style)
    flow = (n.start, n.end - 1) if n.flow else None
    if n.kind == "seq":
        return Lit(span, "list", [lit(text, x) for x in n.value], brackets=flow)
    if n.kind != "map":
        return computed
    keys = [scalar(k) for k, _ in n.value]
    if not all(isinstance(k, str) for k in keys) or len(set(keys)) != len(keys):
        return computed
    if any(k.startswith("fn::") or k == "<<" for k in keys):
        if keys != ["fn::toJSON"]:
            return computed
        inner = lit(text, n.value[0][1])
        return Lit(span, "json", inner) if inner.kind == "obj" else computed
    return Lit(span, "obj", {k: lit(text, v) for k, (_, v) in zip(keys, n.value, strict=True)},
               brackets=flow)  # fmt: skip


# --- resources


def short(token: str) -> str:
    """`aws:ec2:SecurityGroup` for `aws:ec2/securityGroup:SecurityGroup` (both are accepted)."""
    pkg, mod, cls = token.split(":")
    return f"{pkg}:{mod.split('/')[0]}:{cls}"


@dataclass
class Resource:
    key: str  # the key in `resources:`
    name: str | None  # the name in the URN; None when it isn't a literal
    type: str | None  # None when it isn't a literal
    key_start: int
    node: Node


def _str(n: Node | None) -> str | None:
    v = scalar(n) if n is not None else _NO
    return v if isinstance(v, str) and "${" not in v else None


def resources(path: Path, text: str) -> list[Resource]:
    res = tree(text, path.name).get("resources")
    if res is None:
        return []
    if res.kind != "map":
        raise _stop(f"`resources` in {path.name} is not a literal map")
    out = []
    for k, v in res.value:
        key = _str(k)
        if key is None or v.kind != "map":
            raise _stop(f"a resource in {path.name} is not a literal map with a literal key")
        name = _str(v.get("name")) if v.get("name") is not None else key
        out.append(Resource(key, name, _str(v.get("type")), k.start, v))
    return out


def is_type(r: Resource, token: str) -> bool:
    return r.type in (token, short(token))


@dataclass
class YamlResource(Construct):
    node: Node | None = None  # the resource's map


def scan(path: Path, text: str, name: str, token: str) -> list[Construct]:
    """Resources of type `token` (full or short form) whose URN name is `name`."""
    crlf = "\r\n" in text
    text = text.replace("\r\n", "\n")
    return [
        YamlResource(
            path,
            "yaml",
            text,
            crlf,
            text,
            r.key_start,
            r.node.start,
            r.node.end - 1,
            "",
            r.key,
            token,
            name,
            r.node,
        )  # fmt: skip
        for r in resources(path, text)
        if r.name == name and is_type(r, token)
    ]


def find(files: list[Path], name: str, token: str) -> list[Construct]:
    out: list[Construct] = []
    for p in files:
        text = p.read_bytes().decode("utf-8", errors="replace")
        if name in text:
            out += scan(p, text, name, token)
    return out


def rescan(c: Construct, new_text: str) -> Construct:
    hits = scan(c.file, new_text, c.construct_id, c.cls)
    if len(hits) != 1:
        raise unsupported(f"the edited {c.file.name}")
    return hits[0]


def props(c: Construct) -> Props:
    assert isinstance(c, YamlResource) and c.node is not None
    p = c.node.get("properties")
    if c.node.get("get") is not None:  # reads an existing resource; nothing here to edit
        return Props({}, None, "yaml", computed=True)
    if p is None:
        return Props({}, None, "yaml")
    lt = lit(c.text, p)
    if lt.kind != "obj":
        return Props({}, None, "yaml", computed=True)
    return Props(lt.value, (p.start, p.end), "yaml")


# --- rendering in the file's own style


def _plain(v: str) -> bool:
    """`v` reads back as the same string written without quotes, in block or flow context."""
    return (
        bool(v)
        and v == v.strip()
        and not set(v) & set(",[]{}#&*!|>'\"%@`")
        and ": " not in v
        and not v.startswith(("-", "?", ":"))
        and str(_RESOLVER.resolve(ScalarNode, v, (True, False))).endswith(":str")
    )


def render(v: Any, quote: str) -> str:
    """A flow-style YAML value; strings keep `quote` ("" = plain when that reads back the same)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        if quote in ("|", ">"):
            raise unsupported("a block scalar")
        if quote == "'":
            return "'" + v.replace("'", "''") + "'"
        return v if quote == "" and _plain(v) else json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(render(x, quote) for x in v) + "]"
    assert isinstance(v, dict)
    return "{" + ", ".join(f"{k}: {render(x, quote)}" for k, x in v.items()) + "}"


def quote_of(lst: Lit) -> str:
    return next((x.quote for x in lst.value if x.kind == "str"), "")


def list_text(text: str, lst: Lit, values: list[Any]) -> str:
    """`values` in place of the list `lst`, flow or block as it is written."""
    q = quote_of(lst)
    if lst.brackets is not None or not values:
        pad = " " if text[lst.span[0] : lst.span[0] + 2] == "[ " and values else ""
        return f"[{pad}{', '.join(render(x, q) for x in values)}{pad}]"
    prefix = text[line_start(text, lst.span[0]) : lst.span[0]]
    if prefix.strip():
        raise unsupported("a block list that doesn't start its line")
    return ("\n" + prefix).join("- " + render(x, q) for x in values)


def item_sep(text: str, item: Lit) -> str:
    """What goes between two items of the block list `item` is in."""
    head = text[line_start(text, item.span[0]) : item.span[0]]
    if not _ITEM.fullmatch(head):
        raise unsupported("a block list item that doesn't start its line")
    return "\n" + head


def edit_item(text: str, item: Lit, vals: dict[str, Any]) -> str:
    """A copy of the map `item` with the values of `vals` replaced, in its own layout. Every key
    must be there already (a missing description is left out)."""
    s0, e0 = item.span
    spans = []
    for k, v in vals.items():
        old = item.value.get(k)
        if old is None:
            if k == "description":
                continue
            raise unsupported(f"an ingress entry without {k}")
        new = list_text(text, old, v) if old.kind == "list" else render(v, old.quote)
        spans.append((old.span[0] - s0, old.span[1] - s0, new))
    if any(k in item.value and k not in vals for k in ("cidrBlocks", "ipv6CidrBlocks")):
        raise unsupported("an ingress entry with both IPv4 and IPv6 CIDRs")
    out = text[s0:e0]
    for s, e, new in sorted(spans, key=lambda x: -x[0]):
        out = out[:s] + new + out[e:]
    return out


def add_key(c: Construct, key: str, value: str) -> str:
    """The text with `key: value` added as the last of the resource's properties."""
    assert isinstance(c, YamlResource) and c.node is not None
    p, t = c.node.get("properties"), c.text
    if p is None or p.kind != "map" or not p.value:
        raise unsupported(f"the properties of '{c.construct_id}'")
    if p.flow:
        e = p.value[-1][1].end
        return t[:e] + f", {key}: {value}" + t[e:]
    prefix = t[line_start(t, p.start) : p.start]
    if prefix.strip():
        raise unsupported(f"the properties of '{c.construct_id}'")
    pos = p.end if t[p.end - 1] == "\n" else line_end(t, p.end)
    head = "" if t[pos - 1] == "\n" else "\n"
    return t[:pos] + head + prefix + f"{key}: {value}\n" + t[pos:]
