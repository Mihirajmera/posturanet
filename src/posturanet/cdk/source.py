"""CDK program source (TypeScript and Python): find a construct by its id and edit literals.

There is deliberately no language parser here. PosturaNet reads only shapes it can be certain
of: a constructor call whose id is a string literal, `addIngressRule` calls with `Peer` and
`Port` literals, a `blockPublicAccess` prop, and `PolicyStatement` action arrays of string
literals. Comments and string contents are masked first, so nothing inside them is matched or
edited. Every other shape stops with UNKNOWN; the synthesized template is the cross-check.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from posturanet.errors import StageStop
from posturanet.synth.hcl_render import DEFAULT_DESCRIPTION
from posturanet.synth.sg_rules import Rule

Lang = Literal["ts", "py"]
SUFFIXES: dict[str, Lang] = {".ts": "ts", ".py": "py"}
_SKIP_DIRS = {
    "node_modules", "cdk.out", ".git", ".venv", "venv", "__pycache__", ".posturanet",
    "test", "tests", "__tests__",
}  # fmt: skip
_PAIRS = {"(": ")", "[": "]", "{": "}"}
BY_HAND = "fix this construct by hand, or make the value a literal and re-run"

Span = tuple[int, int]


def unsupported(what: str) -> StageStop:
    return StageStop(
        "fix",
        f"{what} is not a literal PosturaNet can read; it won't guess",
        [BY_HAND],
        unknown=True,
    )


# --- scanning


def mask(text: str, lang: Lang) -> str:
    """`text` with comments and string contents blanked (quotes and newlines kept), so offsets
    still line up and brackets or names inside them are never seen as code."""
    out = list(text)
    i, n = 0, len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if (lang == "ts" and text.startswith("//", i)) or (lang == "py" and c == "#"):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif lang == "ts" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif c in "'\"" or (lang == "ts" and c == "`"):
            q = text[i : i + 3] if lang == "py" and text[i : i + 3] in ('"""', "'''") else c
            j = i + len(q)
            while j < n and not text.startswith(q, j):
                j += 2 if text[j] == "\\" else 1
            blank(i + len(q), j)
            i = j + len(q)
        else:
            i += 1
    return "".join(out)


def close_of(masked: str, i: int) -> int:
    """Index of the bracket that closes the one at `i`."""
    stack: list[str] = []
    for j in range(i, len(masked)):
        c = masked[j]
        if c in _PAIRS:
            stack.append(_PAIRS[c])
        elif c in ")]}":
            if not stack or stack.pop() != c:
                break
            if not stack:
                return j
    raise unsupported("code with unbalanced brackets")


def _trim(masked: str, s: int, e: int) -> Span:
    while s < e and masked[s].isspace():
        s += 1
    while e > s and masked[e - 1].isspace():
        e -= 1
    return s, e


def items(masked: str, open_i: int, close_i: int) -> list[Span]:
    """Spans of the comma-separated items between two brackets (trailing comma allowed)."""
    out: list[Span] = []
    depth, s = 0, open_i + 1
    for j in range(open_i + 1, close_i):
        c = masked[j]
        if c in _PAIRS:
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(_trim(masked, s, j))
            s = j + 1
    out.append(_trim(masked, s, close_i))
    return [x for x in out if x[0] < x[1]]


def str_lit(text: str, span: Span) -> tuple[str, str] | None:
    """(value, quote) of a plain string literal: no escapes, interpolation or prefixes."""
    m = re.fullmatch(r"(['\"])([^'\"\\\n`]*)\1", text[span[0] : span[1]])
    return (m.group(2), m.group(1)) if m else None


def line_start(text: str, pos: int) -> int:
    return text.rfind("\n", 0, pos) + 1


def line_end(text: str, pos: int) -> int:
    nl = text.find("\n", pos)
    return len(text) if nl < 0 else nl + 1


# --- constructs


@dataclass
class Construct:
    file: Path
    lang: Lang
    text: str  # LF line endings
    crlf: bool
    masked: str
    start: int  # the call, including `new`
    open: int
    close: int
    qualifier: str  # "ec2." in `new ec2.SecurityGroup(`
    var: str | None  # the name it is assigned to
    cls: str
    construct_id: str

    @property
    def line(self) -> int:
        return self.text.count("\n", 0, self.start) + 1

    @property
    def args(self) -> list[Span]:
        return items(self.masked, self.open, self.close)

    def on_disk(self, text: str) -> str:
        return text.replace("\n", "\r\n") if self.crlf else text


def _call_re(cls: str, lang: Lang) -> re.Pattern[str]:
    head = r"\bnew\s+" if lang == "ts" else r"(?<![\w.])"
    return re.compile(head + r"((?:\w+\.)*)" + cls + r"\s*\(")


_ASSIGN = {
    "ts": re.compile(r"[ \t]*(?:(?:export\s+)?(?:const|let|var)\s+)?([\w.]+)\s*(?::[^=\n]+)?=\s*"),
    "py": re.compile(r"[ \t]*([\w.]+)\s*(?::[^=\n]+)?=\s*"),
}


def scan(path: Path, text: str, construct_id: str, cls: str) -> list[Construct]:
    """Every `cls` construct in `text` whose id (second argument) is the literal `construct_id`."""
    lang = SUFFIXES[path.suffix]
    crlf = "\r\n" in text
    text = text.replace("\r\n", "\n")
    masked = mask(text, lang)
    out = []
    for m in _call_re(cls, lang).finditer(masked):
        o = m.end() - 1
        c = close_of(masked, o)
        args = items(masked, o, c)
        lit = str_lit(text, args[1]) if len(args) >= 2 else None
        if lit is None or lit[0] != construct_id:
            continue
        a = _ASSIGN[lang].fullmatch(masked[line_start(masked, m.start()) : m.start()])
        var = a.group(1) if a else None
        out.append(
            Construct(
                path, lang, text, crlf, masked, m.start(), o, c, m.group(1), var, cls, construct_id
            )
        )
    return out


def source_files(app: Path) -> list[Path]:
    out = []
    for p in sorted(app.rglob("*")):
        if p.suffix not in SUFFIXES or not p.is_file():
            continue
        if _SKIP_DIRS & set(p.relative_to(app).parts[:-1]):
            continue
        if p.name.endswith((".d.ts", ".test.ts", ".spec.ts")) or p.name.startswith("test_"):
            continue
        out.append(p)
    return out


def find(app: Path, construct_id: str, cls: str) -> list[Construct]:
    out: list[Construct] = []
    for p in source_files(app):
        text = p.read_bytes().decode("utf-8", errors="replace")
        if construct_id in text:
            out += scan(p, text, construct_id, cls)
    return out


def rescan(c: Construct, new_text: str) -> Construct:
    """The same construct in the edited file."""
    hits = scan(c.file, new_text, c.construct_id, c.cls)
    if len(hits) != 1:
        raise unsupported(f"the edited {c.file.name}")
    return hits[0]


# --- props (TypeScript object literal, Python keyword arguments)

Entries = dict[str, Span | None]  # key -> value span; None for a shorthand (computed) entry


def _entries(c: Construct, spans: list[Span], what: str) -> Entries:
    out: Entries = {}
    sep = ":" if c.lang == "ts" else "="
    for s, e in spans:
        raw = c.masked[s:e]
        if raw.startswith(("...", "**")):
            raise unsupported(f"a spread in {what}")
        m = re.match(r"(\w+)\s*" + sep + r"(?!=)\s*", raw)
        if m:
            out[m.group(1)] = (s + m.end(), e)
        elif c.lang == "ts" and re.fullmatch(r"\w+", raw):
            out[raw] = None
        else:
            raise unsupported(f"an argument of {what}")
    return out


def object_entries(c: Construct, span: Span, what: str) -> tuple[Entries, Span]:
    """Entries of a TS object literal at `span`, and its braces."""
    s, e = span
    if c.masked[s] != "{" or close_of(c.masked, s) != e - 1:
        raise unsupported(what)
    return _entries(c, items(c.masked, s, e - 1), what), (s, e - 1)


def props(c: Construct, what: str) -> tuple[Entries, Span | None]:
    """The construct's props and the brackets new ones go in (None: TS call without props)."""
    args = c.args
    if c.lang == "ts":
        if len(args) > 3:
            raise unsupported(f"{what} arguments")
        if len(args) < 3:
            return {}, None
        return object_entries(c, args[2], f"{what} props")
    return _entries(c, args[2:], what), (c.open, c.close)


def append_item(text: str, masked: str, brackets: Span, item: str) -> str:
    """`text` with `item` added as the last entry inside `brackets`, in the same layout."""
    o, cl = brackets
    spans = items(masked, o, cl)
    if not spans:
        pad = " " if masked[o] == "{" else ""
        return text[: o + 1] + pad + item + pad + text[cl:]
    last_end = spans[-1][1]
    trailing = masked[last_end:cl].lstrip().startswith(",")
    if "\n" not in masked[o:cl]:
        return text[:last_end] + ", " + item + text[last_end:]
    first = spans[0][0]
    indent = text[line_start(text, first) : first]
    if indent.strip():
        indent = " " * (len(indent) - len(indent.lstrip())) + "  "
    if trailing:
        pos = masked.index(",", last_end) + 1
        return text[:pos] + "\n" + indent + item + "," + text[pos:]
    return text[:last_end] + ",\n" + indent + item + text[last_end:]


# --- security groups

_PEER_ANY = re.compile(r"((?:\w+\.)*)Peer\s*\.\s*(anyIpv4|any_ipv4|anyIpv6|any_ipv6)\s*\(\s*\)")
_PEER_CIDR = re.compile(r"((?:\w+\.)*)Peer\s*\.\s*(ipv4|ipv6)\s*\(\s*(['\"])([^'\"\\\n]+)\3\s*\)")
_PORT = re.compile(r"((?:\w+\.)*)Port\s*\.\s*(\w+)\s*(?:\(\s*([\d\s,]*?)\s*\))?")
_PORT_CONST = {"SSH": 22, "HTTP": 80, "HTTPS": 443, "RDP": 3389}
_FULL = {"allTcp": "tcp", "all_tcp": "tcp", "allUdp": "udp", "all_udp": "udp"}
_INGRESS_ARGS = ("peer", "connection", "description", "remote_rule")


@dataclass
class IngressCall:
    start: int
    end: int  # one past the closing paren
    rule: Rule
    description: str | None
    quote: str | None
    peer_q: str
    port_q: str

    @property
    def is_open(self) -> bool:
        return self.rule.is_world


def _peer(text: str) -> tuple[str, str] | None:
    m = _PEER_ANY.fullmatch(text)
    if m:
        return m.group(1), "0.0.0.0/0" if "4" in m.group(2) else "::/0"
    m = _PEER_CIDR.fullmatch(text)
    if not m:
        return None
    try:
        net = ipaddress.ip_network(m.group(4), strict=False)
    except ValueError:
        return None
    return (m.group(1), str(net)) if f"ipv{net.version}" == m.group(2) else None


def _port(text: str) -> tuple[str, int, int, str] | None:
    """(qualifier, from, to, protocol) of a `Port.…` expression."""
    m = _PORT.fullmatch(text)
    if not m:
        return None
    q, name, raw = m.group(1), m.group(2), m.group(3)
    nums = [int(x) for x in raw.split(",")] if raw else []
    if raw is None:
        return (q, _PORT_CONST[name], _PORT_CONST[name], "tcp") if name in _PORT_CONST else None
    if name in ("tcp", "udp") and len(nums) == 1:
        return q, nums[0], nums[0], name
    if name in ("tcpRange", "tcp_range", "udpRange", "udp_range") and len(nums) == 2:
        return q, nums[0], nums[1], name[:3]
    if name in _FULL and not nums:
        return q, 0, 65535, _FULL[name]
    if name in ("allTraffic", "all_traffic") and not nums:
        return q, -1, -1, "-1"
    return None


def ingress_calls(c: Construct) -> list[IngressCall]:
    """Every `addIngressRule` on the construct's variable in its file."""
    if c.var is None:
        return []
    var = re.escape(c.var)
    if len(re.findall(r"(?<![\w.])" + var + r"\s*(?::[^=\n]+)?=(?!=)", c.masked)) != 1:
        raise unsupported(f"`{c.var}`, assigned more than once in {c.file.name},")
    method = "addIngressRule" if c.lang == "ts" else "add_ingress_rule"
    out = []
    for m in re.finditer(r"(?<![\w.])" + var + r"\s*\.\s*" + method + r"\s*\(", c.masked):
        o = m.end() - 1
        cl = close_of(c.masked, o)
        where = f"{c.var}.{method} on line {c.text.count(chr(10), 0, o) + 1}"
        named: dict[str, Span] = {}
        for pos, (s, e) in enumerate(items(c.masked, o, cl)):
            k = re.match(r"(\w+)\s*=(?!=)\s*", c.masked[s:e]) if c.lang == "py" else None
            if k:
                named[k.group(1)] = (s + k.end(), e)
            elif pos < len(_INGRESS_ARGS):
                named[_INGRESS_ARGS[pos]] = (s, e)
            else:
                raise unsupported(f"the arguments of {where}")
        if set(named) - set(_INGRESS_ARGS[:3]):
            raise unsupported(f"the arguments of {where} (a remote rule)")
        raw = {k: re.sub(r"\s+", " ", c.text[s:e]) for k, (s, e) in named.items()}
        peer = _peer(raw.get("peer", ""))
        port = _port(raw.get("connection", ""))
        if peer is None or port is None:
            raise unsupported(f"the peer or port of {where}")
        desc = str_lit(c.text, named["description"]) if "description" in named else None
        out.append(
            IngressCall(
                m.start(),
                cl + 1,
                Rule(peer[1], port[1], port[2], port[3]),
                desc[0] if desc else None,
                desc[1] if desc else None,
                peer[0],
                port[0],
            )
        )
    return out


def _port_expr(c: Construct, q: str, r: Rule) -> str:
    ts = c.lang == "ts"
    if r.proto == "-1":
        return f"{q}Port.{'allTraffic' if ts else 'all_traffic'}()"
    if r.proto not in ("tcp", "udp"):
        raise StageStop(
            "fix", f"PosturaNet can't write a {r.proto} rule as a CDK Port yet", [BY_HAND]
        )
    if r.from_port == r.to_port:
        return f"{q}Port.{r.proto}({r.from_port})"
    if (r.from_port, r.to_port) == (0, 65535):
        return f"{q}Port.{'all' + r.proto.title() if ts else 'all_' + r.proto}()"
    name = f"{r.proto}Range" if ts else f"{r.proto}_range"
    return f"{q}Port.{name}({r.from_port}, {r.to_port})"


def _description(calls: list[IngressCall], r: Rule) -> tuple[str, str | None]:
    for k in calls:
        o = k.rule
        if (
            k.is_open
            and k.description
            and (o.proto == "-1" or o.from_port <= r.from_port <= o.to_port)
        ):
            return k.description, k.quote
    return DEFAULT_DESCRIPTION, None


def render_sg(c: Construct, calls: list[IngressCall], added: list[Rule]) -> str:
    """New source text: open `addIngressRule` calls removed, the synthesized rules where the
    first one was, in that call's style."""
    text, masked = c.text, c.masked
    open_calls = [k for k in calls if k.is_open]
    method = "addIngressRule" if c.lang == "ts" else "add_ingress_rule"
    edits: list[tuple[int, int, str]] = []
    for idx, k in enumerate(open_calls):
        ls, le = line_start(text, k.start), line_end(text, k.end)
        tail = masked[k.end : le].strip()
        if masked[ls : k.start].strip() or tail not in ("", ";"):
            raise unsupported(f"a {method} call that isn't a statement on its own line")
        indent, semi = text[ls : k.start], ";" if tail == ";" else ""
        lines = []
        for r in added if idx == 0 else []:
            desc, quote = _description(calls, r)
            q = quote or ("'" if c.lang == "ts" else '"')
            q = '"' if q in desc and q == "'" else "'" if q in desc else q
            peer = f"{k.peer_q}Peer.ipv{r.net.version}({q}{r.cidr}{q})"
            port = _port_expr(c, k.port_q, r)
            lines.append(f"{indent}{c.var}.{method}({peer}, {port}, {q}{desc}{q}){semi}\n")
        edits.append((ls, le, "".join(lines)))
    for s, e, new in sorted(edits, key=lambda x: -x[0]):
        text = text[:s] + new + text[e:]
    return text


def norm(r: Rule) -> Rule:
    # protocol -1 has no ports; templates and EC2 may write any.
    return (
        Rule(str(r.net), -1, -1, r.proto)
        if r.proto == "-1"
        else Rule(str(r.net), r.from_port, r.to_port, r.proto)
    )


def source_rules(c: Construct) -> list[Rule]:
    return sorted({norm(k.rule) for k in ingress_calls(c)})


# --- S3 Block Public Access

_BPA_ANY = re.compile(
    r"(?:new)?(?:\w+\.)*BlockPublicAccess(?:\.\w+|\(\{?(?:\w+[:=](?:true|false|True|False),?)*\}?\))"
)


def _keys(c: Construct) -> tuple[str, str]:
    return ("blockPublicAccess", "publicReadAccess") if c.lang == "ts" else (
        "block_public_access", "public_read_access")  # fmt: skip


def _bpa_expr(c: Construct) -> str:
    if c.qualifier:
        return f"{c.qualifier}BlockPublicAccess.BLOCK_ALL"
    imports = r"import\s*\{[^}]*\bBlockPublicAccess\b" if c.lang == "ts" else (
        r"from\s+[\w.]+\s+import\s+\(?[^)\n]*(?:\n[^)\n]*)*?\bBlockPublicAccess\b")  # fmt: skip
    if not re.search(imports, c.masked):
        raise StageStop(
            "fix",
            f"{c.file.name} doesn't import BlockPublicAccess, and PosturaNet won't add imports",
            ["import BlockPublicAccess next to Bucket, then re-run"],
            unknown=True,
        )
    return "BlockPublicAccess.BLOCK_ALL"


def blocks_all(c: Construct) -> bool:
    key, _ = _keys(c)
    span = props(c, "the Bucket")[0].get(key)
    return span is not None and bool(
        re.fullmatch(
            r"(?:\w+\.)*BlockPublicAccess\.BLOCK_ALL",
            re.sub(r"\s+", "", c.masked[span[0] : span[1]]),
        )
    )


def render_s3(c: Construct) -> tuple[str, str]:
    """(new text, what changed) setting the bucket's Block Public Access to BLOCK_ALL."""
    key, public = _keys(c)
    entries, brackets = props(c, "the Bucket")
    if public in entries:
        span = entries[public]
        val = c.masked[span[0] : span[1]] if span else ""
        if val in ("true", "True"):
            raise StageStop(
                "fix",
                f"{c.var or 'the bucket'} sets {public}, which BLOCK_ALL forbids (cdk synth fails)",
                ["move public reads to CloudFront with origin access control, then re-run"],
                why="PosturaNet won't remove access the code asks for on purpose",
            )
        if val not in ("false", "False"):
            raise unsupported(f"{public}")
    new_val = _bpa_expr(c)
    if key in entries:
        span = entries[key]
        if span is None:
            raise unsupported(key)
        old = re.sub(r"\s+", "", c.masked[span[0] : span[1]])
        if blocks_all(c):
            raise StageStop(
                "fix",
                "the code already sets BLOCK_ALL, so the live bucket has drifted",
                ["deploy the app through your pipeline; the fix is already in the code"],
                why="PosturaNet fixes code, and this code is already fixed; the live bucket isn't",
            )
        if not _BPA_ANY.fullmatch(old):
            raise unsupported(key)
        old_text = re.sub(r"\s+", " ", c.text[span[0] : span[1]])
        return c.text[: span[0]] + new_val + c.text[span[1] :], f"{key}: {old_text} → BLOCK_ALL"
    item = f"{key}: {new_val}" if c.lang == "ts" else f"{key}={new_val}"
    if brackets is None:
        item, brackets = "{ " + item + " }", (c.open, c.close)
    return append_item(c.text, c.masked, brackets, item), f"{key}: BLOCK_ALL (added)"


# --- IAM managed policies


@dataclass
class SourceStatement:
    actions: list[str] | None  # None: no `actions` (notActions, or none)
    span: Span | None  # the array literal
    quote: str


def statements(c: Construct) -> list[SourceStatement]:
    """`PolicyStatement`s written inside the construct call, in order."""
    out = []
    key = "actions"
    for m in _call_re("PolicyStatement", c.lang).finditer(c.masked, c.open, c.close):
        o = m.end() - 1
        cl = close_of(c.masked, o)
        spans = items(c.masked, o, cl)
        if c.lang == "ts":
            if len(spans) != 1:
                raise unsupported("PolicyStatement props")
            entries, _ = object_entries(c, spans[0], "PolicyStatement props")
        else:
            entries = _entries(c, spans, "PolicyStatement")
        span = entries.get(key)
        if key in entries and span is None:
            raise unsupported("PolicyStatement actions")
        if span is None:
            out.append(SourceStatement(None, None, "'"))
            continue
        s, e = span
        if c.masked[s] != "[" or close_of(c.masked, s) != e - 1:
            raise unsupported("PolicyStatement actions")
        lits = [str_lit(c.text, x) for x in items(c.masked, s, e - 1)]
        if any(x is None for x in lits):
            raise unsupported("PolicyStatement actions")
        vals = [x for x in lits if x is not None]
        out.append(SourceStatement([v for v, _ in vals], span, vals[0][1] if vals else "'"))
    return out


def render_actions(c: Construct, st: SourceStatement, actions: list[str]) -> str:
    assert st.span is not None
    s, e = st.span
    lits = [f"{st.quote}{a}{st.quote}" for a in actions]
    spans = items(c.masked, s, e - 1)
    if "\n" not in c.masked[s:e] or not spans:
        return "[" + ", ".join(lits) + "]"
    indent = c.text[line_start(c.text, spans[0][0]) : spans[0][0]]
    close_ind = c.text[line_start(c.text, e - 1) : e - 1]
    if indent.strip() or close_ind.strip():
        return "[" + ", ".join(lits) + "]"
    trailing = "," if c.masked[spans[-1][1] : e - 1].strip().startswith(",") else ""
    return "[\n" + ",\n".join(indent + x for x in lits) + trailing + "\n" + close_ind + "]"


def render_iam(c: Construct, sts: list[SourceStatement], after: dict[int, list[str]]) -> str:
    text = c.text
    for i in sorted(after, reverse=True):
        st = sts[i]
        if st.span is None:
            raise unsupported(f"statement {i + 1} actions")
        text = text[: st.span[0]] + render_actions(c, st, after[i]) + text[st.span[1] :]
    return text
