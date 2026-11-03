"""Rewrite the open `ingress` blocks of the target security group (FR-20).

Only the open blocks change. Their world CIDRs are removed (the block is deleted if nothing
is left) and the synthesized rules are inserted where the first open block was, one block
per port and protocol, in the repo's inline style.
"""

from __future__ import annotations

import difflib
import hashlib
import ipaddress
from collections import defaultdict
from pathlib import Path

from posturanet.models import Diff, FileChange
from posturanet.synth.sg_rules import WORLD, IngressBlock, Rule, SecurityGroupSource
from posturanet.synth.sg_z3 import Synthesis

DEFAULT_DESCRIPTION = "Observed sources kept by PosturaNet"


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _render_block(indent: str, attrs: list[tuple[str, str]]) -> str:
    width = max(len(k) for k, _ in attrs)
    inner = indent + "  "
    lines = [f"{indent}ingress {{"]
    lines += [f"{inner}{k.ljust(width)} = {v}" for k, v in attrs]
    lines.append(f"{indent}}}")
    return "\n".join(lines)


def _cidr_list(cidrs: list[str]) -> str:
    return "[" + ", ".join(_quote(c) for c in cidrs) + "]"


def _sort_cidrs(cidrs: list[str]) -> list[str]:
    nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
    return [str(n) for n in sorted(nets, key=lambda n: (n.version, n.network_address, n.prefixlen))]


def _remainder(block: IngressBlock) -> str | None:
    v4 = [c for c in block.cidr_blocks if c not in WORLD]
    v6 = [c for c in block.ipv6_cidr_blocks if c not in WORLD]
    if not v4 and not v6 and not block.extras:
        return None
    attrs: list[tuple[str, str]] = []
    if block.description is not None:
        attrs.append(("description", _quote(block.description)))
    attrs += [
        ("from_port", str(block.from_port)),
        ("to_port", str(block.to_port)),
        ("protocol", _quote(block.protocol)),
    ]
    if v4:
        attrs.append(("cidr_blocks", _cidr_list(v4)))
    if v6:
        attrs.append(("ipv6_cidr_blocks", _cidr_list(v6)))
    attrs += [(k, " ".join(v.split())) for k, v in block.extras.items()]
    return _render_block(block.indent, attrs)


def _new_blocks(added: list[Rule], open_blocks: list[IngressBlock]) -> list[str]:
    groups: dict[tuple[int, int, str], list[str]] = defaultdict(list)
    for r in added:
        groups[(r.from_port, r.to_port, r.proto)].append(r.cidr)
    indent = open_blocks[0].indent
    out = []
    for (fp, tp, proto), cidrs in sorted(groups.items()):
        desc = next(
            (
                b.description
                for b in open_blocks
                if b.description and (b.from_port <= fp <= b.to_port or b.protocol == "-1")
            ),
            DEFAULT_DESCRIPTION,
        )
        attrs = [
            ("description", _quote(desc)),
            ("from_port", str(fp)),
            ("to_port", str(tp)),
            ("protocol", _quote(proto)),
            ("cidr_blocks", _cidr_list(_sort_cidrs(cidrs))),
        ]
        out.append(_render_block(indent, attrs))
    return out


def render(sg: SecurityGroupSource, synth: Synthesis) -> str:
    """New file content with the open blocks rewritten."""
    text = sg.text
    open_blocks = [b for b in sg.blocks if b.is_open]
    pieces: list[str] = []
    cursor = 0
    for idx, block in enumerate(open_blocks):
        pieces.append(text[cursor : block.start])
        replacement: list[str] = []
        if idx == 0:
            replacement += _new_blocks(synth.added, open_blocks) if synth.added else []
        rest = _remainder(block)
        if rest is not None:
            replacement.append(rest)
        cursor = block.end
        if replacement:
            pieces.append("\n\n".join(replacement))
        else:
            # Drop the whole line(s), plus one blank line before, so no gap is left.
            cursor = _eat_newline(text, cursor)
            pieces[-1] = _trim_blank_line(pieces[-1])
    pieces.append(text[cursor:])
    return "".join(pieces)


def _eat_newline(text: str, pos: int) -> int:
    return pos + 1 if text.startswith("\n", pos) else pos


def _trim_blank_line(chunk: str) -> str:
    if chunk.endswith("\n\n"):
        return chunk[:-1]
    return chunk


def unified_diff(path: str, old: str, new: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def make_diff(repo: Path, sg: SecurityGroupSource, synth: Synthesis, target_address: str) -> Diff:
    rel = sg.file.resolve().relative_to(repo.resolve()).as_posix()
    new = render(sg, synth)
    if b"\r\n" in sg.file.read_bytes():
        new_on_disk = new.replace("\r\n", "\n").replace("\n", "\r\n")
    else:
        new_on_disk = new
    udiff = unified_diff(rel, sg.text, new)
    before = [r.label() for r in synth.removed]
    after = [r.label() for r in synth.added]
    summary = (
        f"{', '.join(before)} → {', '.join(after)} ({len(after)} rule{'s' * (len(after) != 1)})"
        if after
        else f"remove {', '.join(before)}"
    )
    return Diff(
        target_address=target_address,
        files=[FileChange(path=rel, unified_diff=udiff, new_content=new_on_disk)],
        summary=summary,
        rules_before=before,
        rules_after=after,
        sha256=hashlib.sha256(udiff.encode("utf-8")).hexdigest(),
    )
