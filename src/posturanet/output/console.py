"""Render a RunRecord as CLI text (docs/04_DESIGN_SYSTEM.md section 2) or JSON."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, TextIO

from posturanet import __version__
from posturanet.models import RunRecord, StageStatus
from posturanet.output.symbols import ASCII, BULLET, UNICODE, to_ascii

if TYPE_CHECKING:
    from posturanet.gate import GateResult

_NAME_WIDTH = 12


def wants_ascii(stream: TextIO) -> bool:
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
    return encoding != "utf8"


def render_text(record: RunRecord, *, ascii_mode: bool = False) -> str:
    symbols = ASCII if ascii_mode else UNICODE
    bullet = BULLET["ascii" if ascii_mode else "unicode"]
    sym_width = max(len(s) for s in symbols.values())

    lines = [f"PosturaNet {record.agent_version} · {record.command} · {record.target}", ""]
    for stage in record.stages:
        sym = symbols[stage.status].ljust(sym_width)
        lines.append(f"  {sym} {stage.name.ljust(_NAME_WIDTH)}{stage.summary}")
        if stage.status is StageStatus.FAIL or stage.expand:
            lines.extend(f"  {' ' * sym_width} {' ' * _NAME_WIDTH}{d}" for d in stage.details)

    if record.diff and record.result in ("DRY RUN", "VALIDATED"):
        lines += ["", "Proposed change"]
        for fc in record.diff.files:
            lines += [f"  {d}" for d in fc.unified_diff.splitlines()]

    lines += ["", f"Result   {record.result} · {record.result_detail}"]
    if record.pr_url:
        lines.append(f"PR       {record.pr_url}")
    if record.why and record.result == "STOPPED":
        lines.append(f"Why      {record.why}")
    if record.unknowns:
        lines += ["", "Unknowns"] + [f"  {bullet} {u}" for u in record.unknowns]
    if record.next_steps:
        lines += ["", "Next"] + [f"  {bullet} {s}" for s in record.next_steps]

    text = "\n".join(lines) + "\n"
    return to_ascii(text) if ascii_mode else text


def render_json(record: RunRecord) -> str:
    return record.model_dump_json(indent=2, by_alias=True) + "\n"


def write(text: str, stream: TextIO | None = None) -> None:
    (stream or sys.stdout).write(text)


def render_gate(result: GateResult, ascii_mode: bool = False) -> str:
    """Contract check output (design system section 7)."""
    lines = [f"PosturaNet {__version__} · contract check", "", result.summary]
    for r in result.results:
        if r.status == "PASS":
            continue
        sym = "✗" if r.status == "BLOCK" else "?"
        lines += ["", f"{sym} {r.address}"] + [f"  {reason}" for reason in r.reasons]
        if r.status == "BLOCK":
            if r.caused_by:
                lines.append(f"  caused by: {r.caused_by}")
            lines.append(
                "  → keep the rule, or update the contract in the same PR with owner approval"
            )
    text = "\n".join(lines) + "\n"
    return to_ascii(text) if ascii_mode else text
