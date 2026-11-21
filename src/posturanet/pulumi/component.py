"""Resources created inside a component resource (FR-10c).

A call inside a component's class is shared by every instance of the component, so PosturaNet
edits it only when one class (TypeScript, Python) or constructor function (Go) in the program
registers the component's type token, the program instantiates it exactly once, and the stack
export holds exactly one component of that type, directly under the stack. Inside it, the
target is the one call of the resource's class whose name is the URN's name as a literal, or
else the only call of that class when its name is computed. Anything else stops with UNKNOWN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from posturanet.cdk import source as cdk_source
from posturanet.cdk.source import Construct, Span, close_of, items, line_start, str_lit
from posturanet.pulumi.source import LANGS, InComponent, _go_mask, scan, trusted

_TS_CLASS = re.compile(r"\bclass\s+(\w+)\s+extends\s+(?:[\w.]+\.)?ComponentResource\b[^{]*\{")
_CS_CLASS = re.compile(r"\bclass\s+(\w+)\s*:\s*(?:[\w.]+\.)?ComponentResource\b[^{]*\{")
_PY_CLASS = re.compile(r"^([ \t]*)class\s+(\w+)\s*\(([^)]*)\)\s*:", re.M)
_GO_FUNC = re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\(")
# The call that registers the component type, per language (its first argument is the token).
_REGISTER = {
    "ts": re.compile(r"\bsuper\s*\("),
    "py": re.compile(r"\bsuper\s*\([^)]*\)\s*\.\s*__init__\s*\("),
    "go": re.compile(r"\.\s*RegisterComponentResource\s*\("),
    "cs": re.compile(r":\s*base\s*\("),
}


@dataclass
class Component:
    file: Path
    name: str  # the class or Go function name
    body: Span  # in the file's LF text
    line: int


def _read(path: Path) -> tuple[str, str]:
    text = path.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
    return text, _mask(path, text)


def _mask(path: Path, text: str) -> str:
    lang = LANGS[path.suffix]
    return _go_mask(text) if lang == "go" else cdk_source.mask(text, lang)


def _py_body(masked: str, m: re.Match[str]) -> Span:
    """The indented block after a Python `class …:` line."""
    indent = len(m.group(1))
    s = cdk_source.line_end(masked, m.end())
    pos = s
    while pos < len(masked):
        end = cdk_source.line_end(masked, pos)
        line = masked[pos:end]
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        pos = end
    return s, pos


def _bodies(path: Path, text: str, masked: str) -> list[tuple[str, Span]]:
    lang = LANGS[path.suffix]
    if lang in ("ts", "cs"):
        rx = _TS_CLASS if lang == "ts" else _CS_CLASS
        return [(m.group(1), (m.end() - 1, close_of(masked, m.end() - 1) + 1))
                for m in rx.finditer(masked)]  # fmt: skip
    if lang == "py":
        return [(m.group(2), _py_body(masked, m)) for m in _PY_CLASS.finditer(masked)
                if re.search(r"\bComponentResource\b", m.group(3))]  # fmt: skip
    out = []
    for m in _GO_FUNC.finditer(masked):
        params_close = close_of(masked, m.end() - 1)
        brace = masked.find("{", params_close)
        if brace < 0 or "\n" in masked[params_close:brace]:
            continue  # results and body open on the signature's line in gofmt'd code
        out.append((m.group(1), (brace, close_of(masked, brace) + 1)))
    return out


def registered(path: Path, text: str, masked: str, token: str) -> list[Component]:
    """Classes (or Go functions) in one file whose body registers `token`."""
    lang = LANGS[path.suffix]
    out = []
    for name, (s, e) in _bodies(path, text, masked):
        for m in _REGISTER[lang].finditer(masked, s, e):
            args = items(masked, m.end() - 1, close_of(masked, m.end() - 1))
            lit = str_lit(text, args[0]) if args else None
            if lit is not None and lit[0] == token:
                out.append(Component(path, name, (s, e), text.count("\n", 0, s) + 1))
                break
    return out


def find(files: list[Path], token: str) -> list[Component]:
    out: list[Component] = []
    for f in files:
        text, masked = _read(f)
        if token in text:
            out += registered(f, text, masked, token)
    return out


def uses(files: list[Path], comp: Component) -> int:
    """How many times the program instantiates the component (by its class or function name)."""
    n = 0
    for f in files:
        text, masked = _read(f)
        lang = LANGS[f.suffix]
        head = r"\bnew\s+" if lang in ("ts", "cs") else r"(?<![\w.])"
        for m in re.finditer(head + r"(?:\w+\.)*" + re.escape(comp.name) + r"\s*\(", masked):
            before = masked[line_start(masked, m.start()) : m.start()]
            if re.search(r"(?:\bclass|\bdef|\bfunc(?:\s*\([^)]*\))?|\bsuper\s*\()\s*$", before):
                continue  # the definition itself, or `super(Name, self)`
            n += 1
    return n


def children(comp: Component, text: str, cls: str, module: str, token: str) -> list[Construct]:
    """Calls of `<…module.>cls` inside the component's body, named or not."""
    s, e = comp.body
    return [
        InComponent(
            **{f.name: getattr(c, f.name) for f in fields(Construct)},
            component=token,
            module=module,
        )
        for c in scan(comp.file, text, None, cls)
        if s <= c.start < e and trusted(c.lang, c.qualifier, c.masked, module)
    ]


def pick(calls: list[Construct], name: str) -> Construct | str:
    named = [c for c in calls if c.construct_id == name]
    if len(named) == 1:
        return named[0]
    computed = [c for c in calls if not c.construct_id]
    if not named and len(calls) == 1 and computed:
        return computed[0]
    return (
        f"{len(calls)} calls of the class in the component ({len(named)} named '{name}'); "
        "can't tell which one made it"
    )


def rescan(c: InComponent, new_text: str) -> Construct:
    """The same call in the edited file: same component body, same name (or the only call)."""
    text = new_text.replace("\r\n", "\n")
    comps = registered(c.file, text, _mask(c.file, text), c.component)
    if len(comps) != 1:
        raise cdk_source.unsupported(f"the edited {c.file.name}")
    hit = pick(children(comps[0], new_text, c.cls, c.module, c.component), c.construct_id)
    if isinstance(hit, str):
        raise cdk_source.unsupported(f"the edited {c.file.name}")
    return hit
