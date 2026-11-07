"""Render a RunRecord as CLI text (docs/04_DESIGN_SYSTEM.md section 4) or JSON."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, TextIO

from posturanet import __version__
from posturanet.models import RunRecord, StageStatus
from posturanet.output.style import PLAIN, Style
from posturanet.output.symbols import ASCII, UNICODE, to_ascii

if TYPE_CHECKING:
    from posturanet.gate import GateResult

_NAME_WIDTH = 12
_LABEL_WIDTH = 12

_STATUS_TOKEN = {
    StageStatus.OK: "success",
    StageStatus.FAIL: "critical",
    StageStatus.WARN: "warning",
    StageStatus.UNKNOWN: "muted",
    StageStatus.SKIPPED: "muted",
}
_RESULT_TOKEN = {
    "OPENED": "success",
    "VALIDATED": "success",
    "CONFIRMED": "success",
    "PASS": "success",
    "DRY RUN": "accent",
    "WATCHING": "accent",
    "STOPPED": "warning",
    "NOT APPLIED": "warning",
    "STILL FAILING": "critical",
    "REGRESSED": "critical",
    "FAIL": "critical",
    "BLOCK": "critical",
}


def wants_ascii(stream: TextIO) -> bool:
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
    return encoding != "utf8"


def _detail(line: str, style: Style) -> str:
    """Evidence and reasoning lines: a trailing `! …` note is a warning."""
    head, sep, note = line.partition("  ! ")
    return head + (style("warning", f"  ! {note}") if sep else "")


def _diff_line(line: str, style: Style) -> str:
    if line.startswith(("+++", "---")):
        return style("bold", line)
    if line.startswith("+"):
        return style("success", line)
    if line.startswith("-"):
        return style("critical", line)
    if line.startswith("@@"):
        return style("accent", line)
    return style("muted", line)


def _labelled(label: str, rows: list[str], style: Style, prefix: str = "") -> list[str]:
    """`Label       first row` then continuation rows aligned under it (design system 4.2)."""
    out = []
    for i, row in enumerate(rows):
        name = style("bold", label.ljust(_LABEL_WIDTH)) if i == 0 else " " * _LABEL_WIDTH
        out.append(f"{name}{prefix}{row}")
    return out


def render_text(record: RunRecord, *, ascii_mode: bool = False, style: Style = PLAIN) -> str:
    symbols = ASCII if ascii_mode else UNICODE
    sym_width = max(len(s) for s in symbols.values())
    dot = " · "

    header = dot.join([record.command, record.target])
    lines = [
        f"{style('bold', 'PosturaNet')} {style('muted', record.agent_version)}{dot}{header}",
        "",
    ]
    for stage in record.stages:
        token = _STATUS_TOKEN[stage.status]
        sym = style(token, symbols[stage.status].ljust(sym_width))
        name = style("bold", stage.name.ljust(_NAME_WIDTH))
        lines.append(f"  {sym} {name}{stage.summary}")
        if stage.status is StageStatus.FAIL or stage.expand:
            pad = f"  {' ' * sym_width} {' ' * _NAME_WIDTH}"
            lines.extend(f"{pad}{_detail(d, style)}" for d in stage.details)

    if record.diff and record.result in ("DRY RUN", "VALIDATED"):
        lines += ["", style("bold", "Proposed change")]
        for fc in record.diff.files:
            lines += [f"  {_diff_line(d, style)}" for d in fc.unified_diff.splitlines()]

    state = style(_RESULT_TOKEN.get(record.result, "bold"), record.result)
    result = f"{state}{dot}{record.result_detail}" if record.result_detail else state
    lines += [""] + _labelled("Result", [result], style)
    if record.pr_url:
        lines += _labelled("PR", [style("accent", record.pr_url)], style)
    if record.why and record.result == "STOPPED":
        lines += _labelled("Why", [record.why], style)
    if record.unknowns:
        lines += _labelled("Unknowns", record.unknowns, style)
    if record.next_steps:
        lines += _labelled("Next", record.next_steps, style, prefix=style("accent", "→ "))

    text = "\n".join(lines) + "\n"
    return to_ascii(text) if ascii_mode else text


def render_json(record: RunRecord) -> str:
    return record.model_dump_json(indent=2, by_alias=True) + "\n"


def write(text: str, stream: TextIO | None = None) -> None:
    (stream or sys.stdout).write(text)


def render_gate(result: GateResult, ascii_mode: bool = False, style: Style = PLAIN) -> str:
    """Contract check output (design system section 7)."""
    state, _, rest = result.summary.partition(" · ")
    summary = f"{style(_RESULT_TOKEN.get(state, 'bold'), state)} · {rest}" if rest else state
    header = f"{style('bold', 'PosturaNet')} {style('muted', __version__)} · contract check"
    lines = [header, "", summary]
    for r in result.results:
        if r.status == "PASS":
            continue
        sym = style("critical", "✗") if r.status == "BLOCK" else style("muted", "?")
        lines += ["", f"{sym} {style('bold', r.address)}"] + [f"  {x}" for x in r.reasons]
        if r.status == "BLOCK":
            if r.caused_by:
                lines.append(style("muted", f"  caused by: {r.caused_by}"))
            fix = "keep the access, or update the contract in the same PR with owner approval"
            lines.append(f"  {style('accent', '→')} {fix}")
    text = "\n".join(lines) + "\n"
    return to_ascii(text) if ascii_mode else text
