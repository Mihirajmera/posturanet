"""Pulumi program source (TypeScript, Python and Go, see `parse_go`): find a resource by its
name and read or edit its literal arguments. YAML programs are read in `yaml_source.py` into the same `Lit` shapes.

The scanning (comment and string masking, bracket matching) is the CDK one: no language
parser, only shapes PosturaNet can be certain of. A constructor call whose first argument is
the resource name as a plain string literal; argument values that are string, number and
boolean literals, arrays, object literals (TypeScript), dicts and `…Args(…)` calls (Python),
and `JSON.stringify(…)` / `json.dumps(…)` of those. Anything else reads as COMPUTED, and every
decision that meets a COMPUTED value stops with UNKNOWN.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from posturanet.cdk import source as cdk_source
from posturanet.cdk.source import Construct, Lang, Span, close_of, items, str_lit, unsupported
from posturanet.errors import StageStop

SUFFIX: dict[str, str] = {"nodejs": ".ts", "python": ".py", "go": ".go"}
LANGS: dict[str, Lang] = {**cdk_source.SUFFIXES, ".go": "go"}
_GO_ASSIGN = re.compile(r"[ \t]*(\w+)\s*(?:,\s*\w+\s*)?:?=\s*")  # `sg, err := `
_GO_SCALAR = re.compile(r"pulumi\s*\.\s*(String|Int|Bool)(?:Ptr)?\s*\(")
_GO_COMPOSITE = re.compile(r"(&?)((?:\w+\.)*\w+)\s*\{")


class Computed:
    """A value PosturaNet can't read from the source (a variable, a call, an interpolation)."""

    def __init__(self, text: str) -> None:
        self.text = text

    def __repr__(self) -> str:
        return f"<computed {self.text[:40]}>"

    def __eq__(self, other: object) -> bool:
        return False  # never equal, so a comparison with deployed state fails closed

    __hash__ = None  # type: ignore[assignment]


def has_computed(v: Any) -> bool:
    if isinstance(v, Computed):
        return True
    if isinstance(v, dict):
        return any(has_computed(x) for x in v.values())
    return isinstance(v, list) and any(has_computed(x) for x in v)


@dataclass
class Lit:
    span: Span
    kind: str  # str | num | bool | list | obj | json | computed
    value: Any = None  # str/int/bool; list[Lit]; dict[str, Lit]; the inner Lit for json
    quote: str = ""
    brackets: Span | None = None  # obj: where new entries go
    call: str = ""  # obj from a Python `…Args(` call: the callee, qualifier included

    def plain(self) -> Any:
        if self.kind == "list":
            return [x.plain() for x in self.value]
        if self.kind == "obj":
            return {k: v.plain() for k, v in self.value.items()}
        if self.kind == "json":
            return self.value.plain()
        if self.kind == "computed":
            return Computed(self.value or "")
        return self.value


def camel(key: str) -> str:
    return re.sub(r"_([a-z0-9])", lambda m: m.group(1).upper(), key)


def _computed(c: Construct, span: Span) -> Lit:
    return Lit(span, "computed", c.text[span[0] : span[1]])


def _kwargs(c: Construct, spans: list[Span], brackets: Span, call: str = "") -> Lit:
    out: dict[str, Lit] = {}
    for s, e in spans:
        m = re.match(r"(\w+)\s*=(?!=)\s*", c.masked[s:e])
        if m is None:
            return _computed(c, (brackets[0], brackets[1] + 1))
        out[m.group(1)] = parse(c, (s + m.end(), e))
    return Lit((brackets[0], brackets[1] + 1), "obj", out, brackets=brackets, call=call)


def parse(c: Construct, span: Span) -> Lit:
    """The literal at `span` of the construct's file (already trimmed)."""
    s, e = span
    raw, masked = c.text[s:e], c.masked[s:e]
    if raw[:1] in "'\"":
        lit = str_lit(c.text, span)
        return Lit(span, "str", lit[0], lit[1]) if lit else _computed(c, span)
    if re.fullmatch(r"-?\d+", raw):
        return Lit(span, "num", int(raw))
    if raw in ("true", "false", "True", "False"):
        return Lit(span, "bool", raw.lower() == "true")
    if masked[:1] in "[{" and close_of(c.masked, s) == e - 1:
        inner = items(c.masked, s, e - 1)
        if masked[0] == "[":
            return Lit(span, "list", [parse(c, x) for x in inner])
        entries: dict[str, Lit] = {}
        sep = ":"
        for a, b in inner:
            m = re.match(r"(?:(\w+)|(['\"])([^'\"\\\n]*)\2)\s*" + sep + r"\s*", c.text[a:b])
            if m is None or c.masked[a:b].startswith(("...", "**")):
                return _computed(c, span)  # a spread, shorthand or computed key
            key = m.group(1) or m.group(3)
            if c.lang == "py" and m.group(1):
                return _computed(c, span)  # `{name: …}` in Python: the key is a variable
            entries[key] = parse(c, (a + m.end(), b))
        return Lit(span, "obj", entries, brackets=(s, e - 1))
    m = re.match(r"((?:\w+\.)*)(\w+)\s*\(", masked)
    if m and close_of(c.masked, s + m.end() - 1) == e - 1:
        o = s + m.end() - 1
        args = items(c.masked, o, e - 1)
        callee = m.group(1) + m.group(2)
        if callee in ("JSON.stringify", "json.dumps") and len(args) == 1:
            inner_lit = parse(c, args[0])
            return Lit(span, "json", inner_lit) if inner_lit.kind == "obj" else _computed(c, span)
        if c.lang == "py" and m.group(2).endswith("Args"):
            return _kwargs(c, args, (o, e - 1), callee)
    return _computed(c, span)


def parse_go(c: Construct, span: Span) -> Lit:
    """The Go literal at `span`: `pulumi.String("…")` / `Int(…)` / `Bool(…)` (and `…Ptr`) of a
    literal, `…Array{…}` slices, `&…Args{Key: …}` structs, and `pulumi.String(`…`)` of a raw
    string holding a JSON object (read as JSON). Anything else is COMPUTED."""
    s, e = span
    masked = c.masked[s:e]
    m = _GO_SCALAR.match(masked)
    if m and close_of(c.masked, s + m.end() - 1) == e - 1:
        args = items(c.masked, s + m.end() - 1, e - 1)
        if len(args) != 1:
            return _computed(c, span)
        a, b = args[0]
        raw = c.text[a:b]
        if m.group(1) == "Int" and re.fullmatch(r"-?\d+", raw):
            return Lit(span, "num", int(raw))
        if m.group(1) == "Bool" and raw in ("true", "false"):
            return Lit(span, "bool", raw == "true")
        if m.group(1) == "String" and raw[:1] == '"':
            lit = str_lit(c.text, (a, b))
            return Lit(span, "str", lit[0], '"') if lit else _computed(c, span)
        if m.group(1) == "String" and raw[:1] == "`" and raw.endswith("`") and len(raw) > 1:
            inner = cdk_source._trim(c.masked, a + 1, b - 1)
            if c.masked[inner[0] : inner[0] + 1] == "{":  # re-masked as JSON by `scan`
                doc = parse(c, inner)
                return Lit(span, "json", doc) if doc.kind == "obj" else _computed(c, span)
            return Lit(span, "str", raw[1:-1], "`") if "\n" not in raw else _computed(c, span)
        return _computed(c, span)
    m = _GO_COMPOSITE.match(masked)
    if m and close_of(c.masked, s + m.end() - 1) == e - 1:
        o = s + m.end() - 1
        typ = m.group(2)
        parts = items(c.masked, o, e - 1)
        if typ.endswith("Array"):
            return Lit(span, "list", [parse_go(c, x) for x in parts], brackets=(o, e - 1),
                       call=typ)  # fmt: skip
        if typ.endswith("Args"):
            out: dict[str, Lit] = {}
            for a, b in parts:
                k = re.match(r"([A-Z]\w*)\s*:\s*", c.masked[a:b])
                if k is None:
                    return _computed(c, span)  # a positional field
                out[k.group(1)[0].lower() + k.group(1)[1:]] = parse_go(c, (a + k.end(), b))
            return Lit(span, "obj", out, brackets=(o, e - 1), call=m.group(1) + typ)
    return _computed(c, span)


def _go_mask(text: str) -> str:
    """Go masking, with raw strings that hold a JSON object masked as JSON instead of blanked,
    so their brackets and strings can be read like a TypeScript object literal."""
    masked = cdk_source.mask(text, "go")
    ticks = [i for i, ch in enumerate(masked) if ch == "`"]
    out = masked
    for a, b in zip(ticks[::2], ticks[1::2], strict=False):
        try:
            ok = isinstance(json.loads(text[a + 1 : b]), dict)
        except ValueError:
            ok = False
        if ok:
            out = out[: a + 1] + cdk_source.mask(text[a + 1 : b], "ts") + out[b:]
    return out


# --- constructor calls


def scan(path: Path, text: str, name: str, cls: str) -> list[Construct]:
    """Every `cls` constructor call in `text` whose first argument is the literal `name`."""
    lang: Lang = LANGS[path.suffix]
    crlf = "\r\n" in text
    text = text.replace("\r\n", "\n")
    go = lang == "go"
    masked = _go_mask(text) if go else cdk_source.mask(text, lang)
    out = []
    for m in cdk_source._call_re("New" + cls if go else cls, lang).finditer(masked):
        o = m.end() - 1
        cl = close_of(masked, o)
        args = items(masked, o, cl)
        at = 1 if go else 0  # Go: New…(ctx, "name", &…Args{…})
        lit = str_lit(text, args[at]) if len(args) > at else None
        if lit is None or lit[0] != name or (go and lit[1] != '"'):
            continue
        assign = _GO_ASSIGN if go else cdk_source._ASSIGN[lang]
        a = assign.fullmatch(masked[cdk_source.line_start(masked, m.start()) : m.start()])
        out.append(
            Construct(
                path,
                lang,
                text,
                crlf,
                masked,
                m.start(),
                o,
                cl,
                m.group(1),
                a.group(1) if a else None,
                cls,
                name,
            )  # fmt: skip
        )
    return out


def find(files: list[Path], name: str, cls: str, module: str) -> list[Construct]:
    """Constructor calls of `<…module.>cls` named `name` (`aws.ec2.SecurityGroup`,
    `ec2.SecurityGroup`; a bare `SecurityGroup` is not trusted to be the AWS class)."""
    out: list[Construct] = []
    for p in files:
        text = p.read_bytes().decode("utf-8", errors="replace")
        if name in text:
            out += [c for c in scan(p, text, name, cls) if c.qualifier.endswith(f"{module}.")]
    return out


def rescan(c: Construct, new_text: str) -> Construct:
    if c.lang == "yaml":
        from posturanet.pulumi import yaml_source

        return yaml_source.rescan(c, new_text)
    hits = scan(c.file, new_text, c.construct_id, c.cls)
    if len(hits) != 1:
        raise unsupported(f"the edited {c.file.name}")
    return hits[0]


@dataclass
class Props:
    """A resource's arguments: camelCase name -> literal, and where new arguments go."""

    values: dict[str, Lit]
    brackets: Span | None  # None: a TS call with no args object
    style: str  # "ts" | "py"
    computed: bool = False  # the args as a whole aren't literal (a variable, a spread)

    def plain(self) -> dict[str, Any]:
        return {k: v.plain() for k, v in self.values.items()}


def props(c: Construct) -> Props:
    if c.lang == "yaml":
        from posturanet.pulumi import yaml_source

        return yaml_source.props(c)
    args = c.args
    if c.lang == "go":
        if len(args) < 3 or c.text[args[2][0] : args[2][1]] == "nil":
            return Props({}, None, "go")
        lit = parse_go(c, args[2])
        if lit.kind != "obj":
            return Props({}, None, "go", computed=True)
        return Props(lit.value, lit.brackets, "go")
    if c.lang == "ts":
        if len(args) < 2:
            return Props({}, None, "ts")
        lit = parse(c, args[1])
        if lit.kind != "obj":
            return Props({}, None, "ts", computed=True)
        return Props(lit.value, lit.brackets, "ts")
    values: dict[str, Lit] = {}
    for pos, (s, e) in enumerate(args[1:]):
        m = re.match(r"(\w+)\s*=(?!=)\s*", c.masked[s:e])
        if m:
            if m.group(1) != "opts":
                values[camel(m.group(1))] = parse(c, (s + m.end(), e))
            continue
        lit = parse(c, (s, e))
        if pos != 0 or lit.kind != "obj":
            return Props({}, None, "py", computed=True)
        return Props({camel(k): v for k, v in lit.value.items()}, lit.brackets, "py")
    return Props(values, (c.open, c.close), "py")


def arg_key(c: Construct, key: str) -> str:
    if c.lang == "go":
        return key[0].upper() + key[1:]
    return key if c.lang == "ts" else re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), key)


def render(v: Any, c: Construct, quote: str, *, py_keys: bool = False) -> str:
    """A literal in the file's language; `py_keys` writes object keys in snake_case."""
    if c.lang == "yaml":
        from posturanet.pulumi import yaml_source

        return yaml_source.render(v, quote)
    if c.lang == "go":
        if isinstance(v, bool):
            return f"pulumi.Bool({'true' if v else 'false'})"
        if isinstance(v, int):
            return f"pulumi.Int({v})"
        if isinstance(v, str):
            return f"pulumi.String({json.dumps(v)})"
        if isinstance(v, list) and all(isinstance(x, str) for x in v):
            return "pulumi.StringArray{" + ", ".join(render(x, c, quote) for x in v) + "}"
        raise unsupported("a Go value PosturaNet doesn't write")
    if isinstance(v, bool):
        return ("True" if v else "False") if c.lang == "py" else ("true" if v else "false")
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return f"{quote}{v}{quote}"
    if isinstance(v, list):
        return "[" + ", ".join(render(x, c, quote, py_keys=py_keys) for x in v) + "]"
    assert isinstance(v, dict)
    if c.lang == "ts":
        return "{ " + ", ".join(f"{k}: {render(x, c, quote)}" for k, x in v.items()) + " }"
    return (
        "{"
        + ", ".join(
            f"{quote}{arg_key(c, k) if py_keys else k}{quote}: {render(x, c, quote)}"
            for k, x in v.items()
        )
        + "}"
    )


@dataclass
class Edits:
    """Replacements in one file's LF text, applied right to left."""

    c: Construct
    spans: list[tuple[int, int, str]] = field(default_factory=list)

    def apply(self) -> str:
        text = self.c.text
        for s, e, new in sorted(self.spans, key=lambda x: -x[0]):
            text = text[:s] + new + text[e:]
        return text


def require_literal(v: Any, what: str) -> None:
    if has_computed(v):
        raise StageStop(
            "locate",
            f"{what} is not a literal PosturaNet can read; it won't guess",
            [cdk_source.BY_HAND],
            unknown=True,
        )
