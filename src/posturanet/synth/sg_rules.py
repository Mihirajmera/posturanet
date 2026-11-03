"""Security group ingress rules as data, and parsing of inline `ingress {}` blocks.

R1 supports inline `ingress` blocks whose values are literals. Anything else that could
change the effective rules (dynamic blocks, variables, separate rule resources, source
security groups or prefix lists on an open rule) stops the run instead of being guessed.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from posturanet.errors import StageStop
from posturanet.locate.hcl_index import block_span, offset_of_line

Net = ipaddress.IPv4Network | ipaddress.IPv6Network

WORLD = frozenset({"0.0.0.0/0", "::/0"})
# Address space that never routes from the internet. Python's `is_private` also includes
# documentation and other special ranges, so it is not used for exposure decisions.
INTERNAL = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
_PROTO_ALIASES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "all": "-1"}


def norm_proto(value: str | int) -> str:
    text = str(value).strip().lower()
    return _PROTO_ALIASES.get(text, text)


@dataclass(frozen=True, order=True)
class Rule:
    """One effective rule: a single CIDR, a port range and a protocol (how AWS counts quota)."""

    cidr: str
    from_port: int
    to_port: int
    proto: str

    @property
    def net(self) -> Net:
        return ipaddress.ip_network(self.cidr, strict=False)

    @property
    def is_world(self) -> bool:
        return self.net.prefixlen == 0

    def admits(self, net: Net, port: int, proto: str) -> bool:
        """True if every address in `net` is allowed on `port`/`proto` by this rule."""
        if self.proto != "-1" and self.proto != norm_proto(proto):
            return False
        # AWS ignores ports for protocol -1, and -1 means "all types" for ICMP.
        if self.proto == "-1" or (self.proto in ("icmp", "icmpv6") and self.from_port == -1):
            port_ok = True
        else:
            port_ok = self.from_port <= port <= self.to_port
        return port_ok and _within(net, self.net)

    def ports_label(self) -> str:
        if self.proto == "-1":
            return "all"
        if self.from_port == self.to_port:
            return f"{self.from_port}/{self.proto}"
        return f"{self.from_port}-{self.to_port}/{self.proto}"

    def label(self) -> str:
        return f"{self.cidr}:{self.ports_label()}"


def is_internal(net: Net) -> bool:
    return any(_within(net, block) for block in INTERNAL)


def _within(inner: Net, outer: Net) -> bool:
    if inner.version != outer.version:
        return False
    return inner.subnet_of(outer)  # type: ignore[arg-type]


def overlaps(a: Net, b: Net) -> bool:
    return a.version == b.version and a.overlaps(b)


@dataclass
class IngressBlock:
    start: int  # offset of the first character of the line holding `ingress {`
    end: int  # one past the closing brace
    indent: str
    from_port: int
    to_port: int
    protocol: str
    cidr_blocks: list[str]
    ipv6_cidr_blocks: list[str]
    description: str | None
    extras: dict[str, str] = field(default_factory=dict)  # other attributes, raw text

    def rules(self) -> list[Rule]:
        proto = norm_proto(self.protocol)
        return [
            Rule(c, self.from_port, self.to_port, proto)
            for c in [*self.cidr_blocks, *self.ipv6_cidr_blocks]
        ]

    @property
    def is_open(self) -> bool:
        return any(c in WORLD for c in [*self.cidr_blocks, *self.ipv6_cidr_blocks])


@dataclass
class SecurityGroupSource:
    file: Path
    text: str
    resource_start: int
    resource_end: int
    blocks: list[IngressBlock]

    def rules(self) -> list[Rule]:
        return sorted({r for b in self.blocks for r in b.rules()})


_INGRESS_HEADER = re.compile(r"^([ \t]*)ingress\s*\{", re.MULTILINE)
_DYNAMIC_INGRESS = re.compile(r'^\s*dynamic\s+"ingress"\s*\{', re.MULTILINE)
_ATTR = re.compile(r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*", re.MULTILINE)
_STRING = re.compile(r'"((?:[^"\\$]|\\.)*)"')
_NUMBER = re.compile(r"-?\d+")
_RULE_RESOURCES = ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule")


def parse_security_group(file: Path, line: int, rtype: str, name: str) -> SecurityGroupSource:
    text = file.read_text(encoding="utf-8")
    start = offset_of_line(text, line)
    brace, end = block_span(text, start)
    body = text[brace + 1 : end - 1]
    if _DYNAMIC_INGRESS.search(body):
        raise StageStop(
            "fix",
            f'{rtype}.{name} uses a dynamic "ingress" block; not supported in R1',
            ["fix this group by hand, or move the open rule to a literal ingress block"],
        )
    _refuse_separate_rules(file.parent, rtype, name)

    blocks: list[IngressBlock] = []
    pos = brace + 1
    while True:
        m = _INGRESS_HEADER.search(text, pos, end - 1)
        if not m:
            break
        if _depth(text, brace, m.start()) != 1:
            pos = m.end()
            continue
        b_open, b_end = block_span(text, m.start())
        blocks.append(_parse_block(text[b_open + 1 : b_end - 1], m.start(), b_end, m.group(1)))
        pos = b_end
    return SecurityGroupSource(file, text, start, end, blocks)


def _depth(text: str, brace: int, pos: int) -> int:
    """Brace depth at `pos` relative to the resource block that opens at `brace`."""
    depth, j, in_str = 0, brace, False
    while j < pos:
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
            j = pos if nl == -1 else nl
            continue
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        j += 1
    return depth


def _strip_comments(body: str) -> str:
    out = []
    for raw in body.splitlines():
        in_str = False
        cut = len(raw)
        for i, ch in enumerate(raw):
            if ch == '"' and (i == 0 or raw[i - 1] != "\\"):
                in_str = not in_str
            elif not in_str and (ch == "#" or raw.startswith("//", i)):
                cut = i
                break
        out.append(raw[:cut])
    return "\n".join(out)


def _parse_block(body: str, start: int, end: int, indent: str) -> IngressBlock:
    clean = _strip_comments(body)
    if "/*" in clean:
        raise StageStop("fix", "block comments inside an ingress block are not supported in R1")
    values: dict[str, str] = {}
    matches = list(_ATTR.finditer(clean))
    for i, m in enumerate(matches):
        stop = matches[i + 1].start() if i + 1 < len(matches) else len(clean)
        values[m.group(1)] = clean[m.end() : stop].strip()

    def number(key: str) -> int:
        raw = values.get(key, "")
        if not _NUMBER.fullmatch(raw):
            raise _non_literal(key, raw)
        return int(raw)

    def string(key: str) -> str | None:
        raw = values.get(key)
        if raw is None:
            return None
        m = _STRING.fullmatch(raw)
        if not m:
            raise _non_literal(key, raw)
        return m.group(1)

    def strings(key: str) -> list[str]:
        raw = values.get(key)
        if raw is None:
            return []
        if not (raw.startswith("[") and raw.endswith("]")):
            raise _non_literal(key, raw)
        inner = raw[1:-1]
        items = _STRING.findall(inner)
        leftover = _STRING.sub("", inner).replace(",", "").strip()
        if leftover:
            raise _non_literal(key, raw)
        return items

    known = {"from_port", "to_port", "protocol", "cidr_blocks", "ipv6_cidr_blocks", "description"}
    protocol = string("protocol")
    if protocol is None:
        raise _non_literal("protocol", "")
    return IngressBlock(
        start=start,
        end=end,
        indent=indent,
        from_port=number("from_port"),
        to_port=number("to_port"),
        protocol=protocol,
        cidr_blocks=strings("cidr_blocks"),
        ipv6_cidr_blocks=strings("ipv6_cidr_blocks"),
        description=string("description"),
        extras={k: v for k, v in values.items() if k not in known},
    )


def _non_literal(key: str, raw: str) -> StageStop:
    shown = raw if len(raw) <= 40 else raw[:37] + "..."
    return StageStop(
        "fix",
        f"ingress {key} is not a literal value ({shown or 'missing'}); not supported in R1",
        ["R1 rewrites only literal ingress blocks; fix this group by hand for now"],
    )


def _refuse_separate_rules(directory: Path, rtype: str, name: str) -> None:
    ref = re.compile(rf"\b{re.escape(rtype)}\.{re.escape(name)}\.id\b")
    header = re.compile(
        r'^\s*resource\s+"(' + "|".join(_RULE_RESOURCES) + r')"\s+"([^"]+)"', re.MULTILINE
    )
    for tf in sorted(directory.glob("*.tf")):
        text = tf.read_text(encoding="utf-8")
        for m in header.finditer(text):
            _, b_end = block_span(text, m.start())
            if ref.search(text[m.start() : b_end]):
                raise StageStop(
                    "fix",
                    f'{rtype}.{name} also has rules in "{m.group(1)}" resources; '
                    "not supported in R1",
                    ["separate rule resources arrive in a later release"],
                )


def rules_from_state(ingress: list[dict[str, Any]]) -> list[Rule]:
    out: set[Rule] = set()
    for r in ingress:
        try:
            fp, tp, proto = int(r["from_port"]), int(r["to_port"]), norm_proto(r["protocol"])
        except (KeyError, TypeError, ValueError):
            continue
        for c in [*(r.get("cidr_blocks") or []), *(r.get("ipv6_cidr_blocks") or [])]:
            out.add(Rule(str(c), fp, tp, proto))
    return sorted(out)


def has_non_cidr_sources(ingress: list[dict[str, Any]]) -> bool:
    return any(
        r.get("security_groups") or r.get("prefix_list_ids") or r.get("self") for r in ingress
    )
