"""CDK program source (TypeScript and Python): find a construct by its id and edit literals.

There is deliberately no language parser here. PosturaNet reads only shapes it can be certain
of: a constructor call whose id is a string literal, `addIngressRule` calls with `Peer` and
`Port` literals, a `blockPublicAccess` prop, and `PolicyStatement` action arrays of string
literals. Comments and string contents are masked first, so nothing inside them is matched or
edited. Every other shape stops with UNKNOWN; the synthesized template is the cross-check.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from posturanet.errors import StageStop
from posturanet.synth.hcl_render import DEFAULT_DESCRIPTION
from posturanet.synth.sg_rules import Rule, norm_proto

Lang = Literal["ts", "py", "yaml", "go"]  # yaml and go: Pulumi programs only (pulumi/)
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
        cstyle = lang in ("ts", "go")
        if (cstyle and text.startswith("//", i)) or (lang == "py" and c == "#"):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif cstyle and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif c in "'\"" or (cstyle and c == "`"):
            q = text[i : i + 3] if lang == "py" and text[i : i + 3] in ('"""', "'''") else c
            raw = lang == "go" and q == "`"  # a Go raw string has no escapes
            j = i + len(q)
            while j < n and not text.startswith(q, j):
                j += 2 if text[j] == "\\" and not raw else 1
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
# Methods that add ingress to the group they're called on → names of their positional args.
_METHODS: dict[str, tuple[str, ...]] = {
    "addIngressRule": ("peer", "connection", "description", "remote_rule"),
    "add_ingress_rule": ("peer", "connection", "description", "remote_rule"),
    "connections.allowFrom": ("peer", "connection", "description"),
    "connections.allow_from": ("peer", "connection", "description"),
    "connections.allowFromAnyIpv4": ("connection", "description"),
    "connections.allow_from_any_ipv4": ("connection", "description"),
}
_KWARGS = {"other": "peer", "port_range": "connection"}  # Python names on `connections`
_CALL = (
    r"(addIngressRule|add_ingress_rule|connections\s*\.\s*"
    r"(?:allowFromAnyIpv4|allow_from_any_ipv4|allowFrom|allow_from))"
)
_ALLOW_TO = re.compile(r"(?<![\w.])([\w.]+)\s*\.\s*connections\s*\.\s*(?:allowTo|allow_to)\s*\(")
_GROUP = re.compile(r"(?!.*\bPeer\b)[A-Za-z_][\w.]*")  # a group variable used as a peer

PeerPorts = tuple[str, int, int]  # (protocol, from, to) of a rule whose source is a group


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


@dataclass
class L1Ingress:
    """A literal `CfnSecurityGroupIngress` whose groupId is the group's variable."""

    construct_id: str
    start: int  # the statement, from its line start
    end: int  # past its line end
    rule: Rule
    description: str | None
    quote: str | None
    removable: bool  # a statement of its own whose value isn't used elsewhere

    @property
    def is_open(self) -> bool:
        return self.rule.is_world


@dataclass
class L1Inline:
    """One literal entry of an L1 `CfnSecurityGroup`'s `securityGroupIngress`."""

    span: Span
    rule: Rule
    description: str | None
    quote: str | None
    style: str  # Python: the `…IngressProperty` callee, or "dict"; TypeScript: ""

    @property
    def is_open(self) -> bool:
        return self.rule.is_world


@dataclass
class SgSource:
    calls: list[IngressCall]  # CIDR rules added on the group's variable
    peers: list[PeerPorts]  # rules whose source is another group (never edited)
    l1: list[L1Ingress]
    inline: list[L1Inline] = field(default_factory=list)  # L1 group: its own ingress prop
    inline_span: Span | None = None

    def rules(self) -> list[Rule]:
        found: list[IngressCall | L1Ingress | L1Inline] = [*self.calls, *self.l1, *self.inline]
        return sorted({norm(k.rule) for k in found})


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


def peer_ports(proto: str, lo: int, hi: int) -> PeerPorts:
    return (proto, -1, -1) if proto == "-1" else (proto, lo, hi)


def _args(c: Construct, o: int, cl: int, names: tuple[str, ...], where: str) -> dict[str, Span]:
    named: dict[str, Span] = {}
    for pos, (s, e) in enumerate(items(c.masked, o, cl)):
        k = re.match(r"(\w+)\s*=(?!=)\s*", c.masked[s:e]) if c.lang == "py" else None
        if k:
            named[_KWARGS.get(k.group(1), k.group(1))] = (s + k.end(), e)
        elif pos < len(names):
            named[names[pos]] = (s, e)
        else:
            raise unsupported(f"the arguments of {where}")
    if set(named) - {"peer", "connection", "description"}:
        raise unsupported(f"the arguments of {where} (a remote rule)")
    return named


def _raw(c: Construct, span: Span) -> str:
    return re.sub(r"\s+", " ", c.text[span[0] : span[1]])


def sg_source(c: Construct) -> SgSource:
    """Every literal way the construct's file adds ingress to it."""
    out = SgSource([], [], [])
    if c.cls == "CfnSecurityGroup":
        out.inline, out.inline_span = _l1_inline(c)
    if c.var is None:
        return out
    var = re.escape(c.var)
    if len(re.findall(r"(?<![\w.])" + var + r"\s*(?::[^=\n]+)?=(?!=)", c.masked)) != 1:
        raise unsupported(f"`{c.var}`, assigned more than once in {c.file.name},")
    if c.cls == "CfnSecurityGroup":  # an L1 has no addIngressRule or connections
        out.l1 = _l1_ingress(c)
        return out
    for m in re.finditer(r"(?<![\w.])" + var + r"\s*\.\s*" + _CALL + r"\s*\(", c.masked):
        method = re.sub(r"\s+", "", m.group(1))
        o = m.end() - 1
        cl = close_of(c.masked, o)
        where = f"{c.var}.{method} on line {c.text.count(chr(10), 0, o) + 1}"
        named = _args(c, o, cl, _METHODS[method], where)
        port = _port(_raw(c, named["connection"])) if "connection" in named else None
        if "peer" in named:
            raw = _raw(c, named["peer"])
            peer = _peer(raw)
            if peer is None and port is not None and _GROUP.fullmatch(raw):
                out.peers.append(peer_ports(port[3], port[1], port[2]))
                continue
        else:
            peer = (c.qualifier, "0.0.0.0/0")  # allowFromAnyIpv4
        if peer is None or port is None:
            raise unsupported(f"the peer or port of {where}")
        desc = str_lit(c.text, named["description"]) if "description" in named else None
        out.calls.append(
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
    for m in _ALLOW_TO.finditer(c.masked):
        o = m.end() - 1
        cl = close_of(c.masked, o)
        args = items(c.masked, o, cl)
        if not args or _raw(c, args[0]) != c.var:
            continue
        where = f"{m.group(1)}.connections.allowTo on line {c.text.count(chr(10), 0, o) + 1}"
        named = _args(c, o, cl, ("peer", "connection", "description"), where)
        port = _port(_raw(c, named["connection"])) if "connection" in named else None
        if port is None:
            raise unsupported(f"the port of {where}")
        out.peers.append(peer_ports(port[3], port[1], port[2]))
    out.l1 = _l1_ingress(c)
    return out


_L1_KEYS = {"groupid", "cidrip", "cidripv6", "ipprotocol", "fromport", "toport", "description"}


def _l1_rule(c: Construct, v: dict[str, Span], what: str) -> tuple[Rule, tuple[str, str] | None]:
    """The CIDR rule (and description literal) of an L1 ingress's literal props."""
    cidr = [str_lit(c.text, v[x]) for x in ("cidrip", "cidripv6") if x in v]
    proto = str_lit(c.text, v["ipprotocol"]) if "ipprotocol" in v else None
    ports = [_raw(c, v[x]) if x in v else "-1" for x in ("fromport", "toport")]
    if len(cidr) != 1 or cidr[0] is None or proto is None:
        raise unsupported(f"the source or protocol of {what}")
    if not all(re.fullmatch(r"-?\d+", p) for p in ports):
        raise unsupported(f"the ports of {what}")
    try:
        rule = Rule(cidr[0][0], int(ports[0]), int(ports[1]), norm_proto(proto[0]))
    except ValueError as exc:
        raise unsupported(f"the source of {what}") from exc
    return rule, str_lit(c.text, v["description"]) if "description" in v else None


# --- L1 constructs: props are CloudFormation properties, written as literals

_KEY = re.compile(r"""(?:(\w+)|(['"])(\w+)\2)\s*([:=])(?!=)\s*""")


def _kv(c: Construct, span: Span, what: str) -> dict[str, Span]:
    """Entries of a literal struct at `span` (a TS object, a Python dict, or a Python
    `…Property(k=v)` call), keyed by name lowercased without underscores."""
    s, e = span
    m = c.masked
    call = re.match(r"[\w.]+\s*\(", m[s:e]) if c.lang == "py" else None
    if m[s] == "{" and close_of(m, s) == e - 1:
        o, sep = s, ":"
    elif call and close_of(m, s + call.end() - 1) == e - 1:
        o, sep = s + call.end() - 1, "="
    else:
        raise unsupported(what)
    out: dict[str, Span] = {}
    for a, b in items(m, o, e - 1):
        k = _KEY.match(c.text, a)  # the text: masking blanks quoted keys
        if k is None or k.group(4) != sep or k.end() >= b or (c.lang == "py" and sep == ":"
                                                              and k.group(1)):  # fmt: skip
            raise unsupported(f"an entry of {what}")
        out[(k.group(1) or k.group(3)).replace("_", "").lower()] = (k.end(), b)
    return out


def _l1_prop(c: Construct, ts: str, py: str) -> Span | None:
    """The value of one prop of an L1 construct, or None when it isn't set."""
    entries, _ = props(c, f"the {c.cls}")
    key = ts if c.lang == "ts" else py
    if key in entries and entries[key] is None:
        raise unsupported(f"{key} of {c.construct_id}")
    return entries.get(key)


def _list(c: Construct, span: Span, what: str) -> list[Span]:
    s, e = span
    if c.masked[s] != "[" or close_of(c.masked, s) != e - 1:
        raise unsupported(what)
    return items(c.masked, s, e - 1)


def _l1_inline(c: Construct) -> tuple[list[L1Inline], Span | None]:
    span = _l1_prop(c, "securityGroupIngress", "security_group_ingress")
    if span is None:
        return [], None
    out = []
    for x in _list(c, span, f"securityGroupIngress of {c.construct_id}"):
        what = f"an ingress entry of {c.construct_id} (line {c.text.count(chr(10), 0, x[0]) + 1})"
        v = _kv(c, x, what)
        if set(v) - (_L1_KEYS - {"groupid"}):
            raise unsupported(what)
        rule, desc = _l1_rule(c, v, what)
        callee = re.match(r"[\w.]+", c.masked[x[0] : x[1]])
        style = "" if c.lang == "ts" else callee.group(0) if callee else "dict"
        out.append(L1Inline(x, rule, desc[0] if desc else None, desc[1] if desc else None, style))
    return out, span


def _l1_ingress(c: Construct) -> list[L1Ingress]:
    assert c.var is not None
    targets = {
        f"{c.var}.{a}"
        for a in ("securityGroupId", "attrGroupId", "security_group_id", "attr_group_id", "ref")
    }
    out = []
    for m in _call_re("CfnSecurityGroupIngress", c.lang).finditer(c.masked):
        o = m.end() - 1
        cl = close_of(c.masked, o)
        if not re.search(r"(?<![\w.])" + re.escape(c.var) + r"\b", c.masked[o:cl]):
            continue  # not about this group
        k = Construct(c.file, c.lang, c.text, c.crlf, c.masked, m.start(), o, cl, m.group(1),
                      None, "CfnSecurityGroupIngress", "")  # fmt: skip
        what = f"the CfnSecurityGroupIngress on line {k.line}"
        args = k.args
        lit = str_lit(c.text, args[1]) if len(args) >= 2 else None
        entries, _ = props(k, what)
        v: dict[str, Span] = {}
        for key, span in entries.items():
            name = key.replace("_", "").lower()
            if name not in _L1_KEYS or span is None:
                raise unsupported(f"{key} of {what}")
            v[name] = span
        if lit is None or "groupid" not in v or _raw(c, v["groupid"]) not in targets:
            raise unsupported(f"the id or groupId of {what}")
        rule, desc = _l1_rule(c, v, what)
        ls, le = line_start(c.text, m.start()), line_end(c.text, cl + 1)
        before = c.masked[ls : m.start()]
        a = _ASSIGN[c.lang].fullmatch(before) if before.strip() else None
        uses = len(re.findall(r"(?<![\w.])" + re.escape(a.group(1)) + r"\b", c.masked)) if a else 1
        removable = (not before.strip() or a is not None) and uses == 1
        removable = removable and c.masked[cl + 1 : le].strip() in ("", ";")
        out.append(
            L1Ingress(
                lit[0],
                ls,
                le,
                rule,
                desc[0] if desc else None,
                desc[1] if desc else None,
                removable,
            )  # fmt: skip
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


def _description(src: SgSource, r: Rule) -> tuple[str, str | None]:
    found: list[IngressCall | L1Ingress | L1Inline] = [*src.calls, *src.l1, *src.inline]
    for k in found:
        o = k.rule
        if (
            k.is_open
            and k.description
            and (o.proto == "-1" or o.from_port <= r.from_port <= o.to_port)
        ):
            return k.description, k.quote
    return DEFAULT_DESCRIPTION, None


def render_sg(c: Construct, src: SgSource, added: list[Rule]) -> str:
    """New source text: open ingress calls and open `CfnSecurityGroupIngress` statements
    removed, the synthesized rules as `addIngressRule` calls where the first one was, in that
    statement's indent and style. Group-peer rules are never touched."""
    if c.cls == "CfnSecurityGroup":
        return _render_l1_sg(c, src, added)
    text, masked = c.text, c.masked
    method = "addIngressRule" if c.lang == "ts" else "add_ingress_rule"
    spans: list[tuple[int, int, str, str, str]] = []  # (from, to, semi, peer_q, port_q)
    for k in src.calls:
        if not k.is_open:
            continue
        ls, le = line_start(text, k.start), line_end(text, k.end)
        tail = masked[k.end : le].strip()
        if masked[ls : k.start].strip() or tail not in ("", ";"):
            raise unsupported(f"an ingress call on `{c.var}` that isn't a statement of its own")
        spans.append((ls, le, ";" if tail == ";" else "", k.peer_q, k.port_q))
    for x in src.l1:
        if not x.is_open:
            continue
        if not x.removable:
            raise unsupported(f"CfnSecurityGroupIngress {x.construct_id}, which isn't removable,")
        semi = ";" if masked[x.start : x.end].rstrip().endswith(";") else ""
        spans.append((x.start, x.end, semi, c.qualifier, c.qualifier))
    spans.sort()
    edits: list[tuple[int, int, str]] = []
    for idx, (ls, le, semi, peer_q, port_q) in enumerate(spans):
        indent = text[ls:le][: len(text[ls:le]) - len(text[ls:le].lstrip(" \t"))]
        lines = []
        for r in added if idx == 0 else []:
            desc, quote = _description(src, r)
            q = quote or ("'" if c.lang == "ts" else '"')
            q = '"' if q in desc and q == "'" else "'" if q in desc else q
            peer = f"{peer_q}Peer.ipv{r.net.version}({q}{r.cidr}{q})"
            port = _port_expr(c, port_q, r)
            lines.append(f"{indent}{c.var}.{method}({peer}, {port}, {q}{desc}{q}){semi}\n")
        edits.append((ls, le, "".join(lines)))
    for s, e, new in sorted(edits, key=lambda x: -x[0]):
        text = text[:s] + new + text[e:]
    return text


def _quoted(s: str, quote: str) -> str:
    q = '"' if quote in s and quote == "'" else "'" if quote in s else quote
    return f"{q}{s}{q}"


def _ingress_entry(c: Construct, src: SgSource, r: Rule, style: str) -> str:
    desc, quote = _description(src, r)
    q = quote or ("'" if c.lang == "ts" else '"')
    lo, hi = (-1, -1) if r.proto == "-1" else (r.from_port, r.to_port)
    v6 = r.net.version == 6
    vals = [_quoted(r.cidr, q), _quoted(r.proto, q), str(lo), str(hi), _quoted(desc, q)]
    if c.lang == "ts":
        keys = ["cidrIpv6" if v6 else "cidrIp", "ipProtocol", "fromPort", "toPort", "description"]
        return "{ " + ", ".join(f"{k}: {v}" for k, v in zip(keys, vals, strict=True)) + " }"
    keys = ["cidr_ipv6" if v6 else "cidr_ip", "ip_protocol", "from_port", "to_port", "description"]
    if style == "dict":
        return "{" + ", ".join(f'"{k}": {v}' for k, v in zip(keys, vals, strict=True)) + "}"
    callee = style or f"{c.qualifier}CfnSecurityGroup.IngressProperty"
    return f"{callee}(" + ", ".join(f"{k}={v}" for k, v in zip(keys, vals, strict=True)) + ")"


def _set_prop(c: Construct, text: str, ts: str, py: str, val: str) -> str:
    """`text` (the construct's file) with a new prop `ts`/`py` = `val` in the construct call."""
    _, brackets = props(c, f"the {c.cls}")
    item = f"{ts}: {val}" if c.lang == "ts" else f"{py}={val}"
    if brackets is None:
        item, brackets = "{ " + item + " }", (c.open, c.close)
    return append_item(text, c.masked, brackets, item)


def _render_l1_sg(c: Construct, src: SgSource, added: list[Rule]) -> str:
    """An L1 group: open entries of its `securityGroupIngress` replaced by the synthesized
    rules in the same list, and open `CfnSecurityGroupIngress` statements removed."""
    edits: list[tuple[int, int, str]] = []
    for x in src.l1:
        if x.is_open and not x.removable:
            raise unsupported(f"CfnSecurityGroupIngress {x.construct_id}, which isn't removable,")
        if x.is_open:
            edits.append((x.start, x.end, ""))
    style = src.inline[0].style if src.inline else ""
    entries = [c.text[k.span[0] : k.span[1]] for k in src.inline if not k.is_open]
    entries += [_ingress_entry(c, src, r, style) for r in added]
    text = c.text
    if src.inline_span is not None:
        s, e = src.inline_span
        edits.append((s, e, _render_list(c, src.inline_span, entries)))
    elif entries:
        text = _set_prop(c, text, "securityGroupIngress", "security_group_ingress",
                         "[" + ", ".join(entries) + "]")  # fmt: skip
        delta = len(text) - len(c.text)
        edits = [(s + delta, e + delta, n) if s > c.close else (s, e, n) for s, e, n in edits]
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
    return sg_source(c).rules()


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


_BPA_FLAGS = ("blockpublicacls", "blockpublicpolicy", "ignorepublicacls", "restrictpublicbuckets")
_L1_BPA = ("publicAccessBlockConfiguration", "public_access_block_configuration")


def _l1_bpa(c: Construct) -> tuple[Span | None, bool]:
    """(the L1 bucket's publicAccessBlockConfiguration, whether all four flags are true)."""
    span = _l1_prop(c, *_L1_BPA)
    if span is None:
        return None, False
    flags = {k: c.masked[s:e].strip() for k, (s, e) in _kv(c, span, _L1_BPA[0]).items()}
    if set(flags) - set(_BPA_FLAGS) or set(flags.values()) - {"true", "false", "True", "False"}:
        raise unsupported(f"{_L1_BPA[0]} of {c.construct_id}")
    return span, all(flags.get(k) in ("true", "True") for k in _BPA_FLAGS)


def _drifted() -> StageStop:
    return StageStop(
        "fix",
        "the code already blocks all public access, so the live bucket has drifted",
        ["deploy the app through your pipeline; the fix is already in the code"],
        why="PosturaNet fixes code, and this code is already fixed; the live bucket isn't",
    )


def _render_l1_s3(c: Construct) -> tuple[str, str]:
    span, ok = _l1_bpa(c)
    if ok:
        raise _drifted()
    if c.lang == "ts":
        flags = (
            "blockPublicAcls",
            "blockPublicPolicy",
            "ignorePublicAcls",
            "restrictPublicBuckets",
        )
        val = "{ " + ", ".join(f"{k}: true" for k in flags) + " }"
    else:
        flags = ("block_public_acls", "block_public_policy", "ignore_public_acls",
                 "restrict_public_buckets")  # fmt: skip
        val = f"{c.qualifier}CfnBucket.PublicAccessBlockConfigurationProperty("
        val += ", ".join(f"{k}=True" for k in flags) + ")"
    key = _L1_BPA[0] if c.lang == "ts" else _L1_BPA[1]
    if span is not None:
        return c.text[: span[0]] + val + c.text[span[1] :], f"{key}: all four flags → true"
    return _set_prop(c, c.text, *_L1_BPA, val), f"{key}: all four flags true (added)"


def blocks_all(c: Construct) -> bool:
    if c.cls == "CfnBucket":
        return _l1_bpa(c)[1]
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
    if c.cls == "CfnBucket":
        return _render_l1_s3(c)
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
            raise _drifted()
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
    """`PolicyStatement`s written inside the construct call, in order (for an L1
    `CfnManagedPolicy`, the statements of its literal `policyDocument`)."""
    if c.cls == "CfnManagedPolicy":
        return _l1_statements(c)
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


def _l1_statements(c: Construct) -> list[SourceStatement]:
    span = _l1_prop(c, "policyDocument", "policy_document")
    if span is None:
        raise unsupported(f"the policyDocument of {c.construct_id}")
    doc = _kv(c, span, "the policyDocument (a literal object)")
    if "statement" not in doc:
        raise unsupported("the policyDocument Statement")
    out = []
    for x in _list(c, doc["statement"], "the policyDocument Statement"):
        st = _kv(c, x, "a policy statement")
        if "action" not in st:
            out.append(SourceStatement(None, None, "'"))
            continue
        s, e = st["action"]
        spans = _list(c, (s, e), "Action") if c.masked[s] == "[" else [(s, e)]
        lits = [str_lit(c.text, y) for y in spans]
        if any(y is None for y in lits):
            raise unsupported("a policy statement Action")
        vals = [y for y in lits if y is not None]
        out.append(SourceStatement([v for v, _ in vals], (s, e), vals[0][1] if vals else "'"))
    return out


def _render_list(c: Construct, span: Span, entries: list[str]) -> str:
    """A list literal of `entries` to replace the one at `span`, in its layout."""
    s, e = span
    spans = items(c.masked, s, e - 1) if c.masked[s] == "[" else []
    if "\n" not in c.masked[s:e] or not spans:
        return "[" + ", ".join(entries) + "]"
    indent = c.text[line_start(c.text, spans[0][0]) : spans[0][0]]
    close_ind = c.text[line_start(c.text, e - 1) : e - 1]
    if indent.strip() or close_ind.strip():
        return "[" + ", ".join(entries) + "]"
    trailing = "," if c.masked[spans[-1][1] : e - 1].strip().startswith(",") else ""
    return "[\n" + ",\n".join(indent + x for x in entries) + trailing + "\n" + close_ind + "]"


def render_actions(c: Construct, st: SourceStatement, actions: list[str]) -> str:
    assert st.span is not None
    return _render_list(c, st.span, [f"{st.quote}{a}{st.quote}" for a in actions])


def render_iam(c: Construct, sts: list[SourceStatement], after: dict[int, list[str]]) -> str:
    text = c.text
    for i in sorted(after, reverse=True):
        st = sts[i]
        if st.span is None:
            raise unsupported(f"statement {i + 1} actions")
        text = text[: st.span[0]] + render_actions(c, st, after[i]) + text[st.span[1] :]
    return text


# --- attribute fixes: CloudFormation property overrides on the L2 construct's default child

_OVERRIDE = re.compile(r"\.\s*(?:addPropertyOverride|add_property_override)\s*\(")


def _value(v: object, lang: Lang) -> str:
    if isinstance(v, bool):
        return ("true" if v else "false") if lang == "ts" else str(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_value(x, lang) for x in v) + "]"
    s = str(v)
    return f"'{s}'" if lang == "ts" and "'" not in s and "\\" not in s else json.dumps(s)


def overrides(c: Construct) -> dict[str, str]:
    """Property path -> value text of every literal property override in the construct's file
    on its variable (`var.node.defaultChild` / `default_child`)."""
    if c.var is None:
        return {}
    child = r"\(?\s*" + re.escape(c.var) + r"\s*\.\s*node\s*\.\s*(?:defaultChild|default_child)"
    if c.cls.startswith("Cfn"):
        child = r"(?<![\w.])" + re.escape(c.var) + r"\s*$"
    out: dict[str, str] = {}
    for m in _OVERRIDE.finditer(c.masked):
        head = c.masked[line_start(c.masked, m.start()) : m.start()]
        if not re.search(child, head):
            continue
        o = m.end() - 1
        args = items(c.masked, o, close_of(c.masked, o))
        path = str_lit(c.text, args[0]) if len(args) == 2 else None
        if path is None:
            raise unsupported(
                f"a property override on `{c.var}` (line {c.text.count(chr(10), 0, o) + 1})"
            )
        out[path[0]] = c.text[args[1][0] : args[1][1]].strip()
    return out


def render_attr(c: Construct, props: list[tuple[str, object]], cfn_cls: str) -> str:
    """New source text with one property override per (CloudFormation path, value), as
    statements right after the construct's own statement."""
    if c.var is None:
        raise unsupported(
            f"the {c.construct_id} construct isn't assigned to a variable, so its properties "
            "can't be overridden; that"
        )
    clash = sorted(set(overrides(c)) & {p for p, _ in props})
    if clash:
        raise unsupported(f"an existing property override of {clash[0]}, which")
    text, masked = c.text, c.masked
    le = line_end(text, c.close + 1)
    tail = masked[c.close + 1 : le].strip()
    if tail not in ("", ";"):
        raise unsupported(f"the statement that creates {c.construct_id}")
    ls = line_start(text, c.start)
    indent = text[ls : ls + len(text[ls:]) - len(text[ls:].lstrip(" \t"))]
    l1 = c.cls.startswith("Cfn")  # an L1 is its own CloudFormation resource
    if c.lang == "ts":
        semi = ";" if tail.endswith(";") else ""
        head = c.var if l1 else f"({c.var}.node.defaultChild as {c.qualifier}{cfn_cls})"
        lines = [
            f"{indent}{head}.addPropertyOverride('{p}', {_value(v, 'ts')}){semi}\n"
            for p, v in props
        ]
    else:
        head = c.var if l1 else f"{c.var}.node.default_child"
        lines = [
            f'{indent}{head}.add_property_override("{p}", {_value(v, "py")})\n' for p, v in props
        ]
    return text[:le] + "".join(lines) + text[le:]
