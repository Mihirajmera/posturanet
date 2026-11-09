"""Render a RunRecord as CLI text (docs/04_DESIGN_SYSTEM.md section 4) or JSON."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, TextIO

from posturanet import __version__
from posturanet.models import RunRecord, StageStatus
from posturanet.output.frame import Frame
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


def header(command: str, target: str, style: Style = PLAIN, version: str = __version__) -> str:
    """`PosturaNet 0.2.0 · command · target`, the title on every framed output."""
    rest = " · ".join(p for p in (command, target) if p)
    return f"{style('bold', 'PosturaNet')} {style('muted', version)} · {rest}"


_CLOSING = {
    "DRY RUN": "Done. Nothing was changed.",
    "VALIDATED": "Done. Nothing was changed; add --open-pr to open the PR.",
    "OPENED": "Done. Review the PR; a person merges it.",
    "STOPPED": "Stopped. No PR opened.",
}


def render_text(
    record: RunRecord,
    *,
    ascii_mode: bool = False,
    style: Style = PLAIN,
    width: int | None = None,
) -> str:
    symbols = ASCII if ascii_mode else UNICODE
    sym_width = max(len(s) for s in symbols.values())
    frame = Frame(ascii_mode, style, width)
    dot = " · "

    lines = frame.open(header(record.command, record.target, style, record.agent_version))
    for stage in record.stages:
        token = _STATUS_TOKEN[stage.status]
        sym = style(token, symbols[stage.status].ljust(sym_width))
        name = style("bold", stage.name.ljust(_NAME_WIDTH))
        lines.append(frame.step(f"{sym} {name}{stage.summary}", token=token))
        if stage.status is StageStatus.FAIL or stage.expand:
            pad = " " * (sym_width + 1 + _NAME_WIDTH)
            lines.extend(frame.bar(f"{pad}{_detail(d, style)}") for d in stage.details)
    lines.append(frame.bar())

    if record.diff and record.result in ("DRY RUN", "VALIDATED"):
        diff = [
            _diff_line(d, style) for fc in record.diff.files for d in fc.unified_diff.splitlines()
        ]
        lines += frame.box("Proposed change", diff)

    result_token = _RESULT_TOKEN.get(record.result, "bold")
    state = style(result_token, record.result)
    rows = _labelled(
        "Result", [f"{state}{dot}{record.result_detail}" if record.result_detail else state], style
    )
    if record.pr_url:
        rows += _labelled("PR", [style("accent", record.pr_url)], style)
    if record.why and record.result == "STOPPED":
        rows += _labelled("Why", [record.why], style)
    if record.unknowns:
        rows += _labelled("Unknowns", record.unknowns, style)
    if record.next_steps:
        rows += _labelled("Next", record.next_steps, style, prefix=style("accent", "→ "))
    lines += frame.box("Result", rows, token=result_token)
    lines += frame.close(_CLOSING.get(record.result, f"Finished: {record.result}."))

    text = "\n".join(lines) + "\n"
    return to_ascii(text) if ascii_mode else text


def render_json(record: RunRecord) -> str:
    return record.model_dump_json(indent=2, by_alias=True) + "\n"


def write(text: str, stream: TextIO | None = None) -> None:
    (stream or sys.stdout).write(text)


def render_gate(
    result: GateResult,
    ascii_mode: bool = False,
    style: Style = PLAIN,
    *,
    framed: bool = True,
    width: int | None = None,
) -> str:
    """Contract check output (design system section 7).

    `framed=False` is the bare form the agent hooks send to a coding agent: no rail or boxes.
    """
    state, _, rest = result.summary.partition(" · ")
    token = _RESULT_TOKEN.get(state, "bold")
    summary = f"{style(token, state)} · {rest}" if rest else style(token, state)
    title = header("contract check", "", style)
    blocks: list[tuple[str, str, list[str]]] = []
    for r in result.results:
        if r.status == "PASS":
            continue
        sym, sym_token = ("✗", "critical") if r.status == "BLOCK" else ("?", "muted")
        body = list(r.reasons)
        if r.status == "BLOCK":
            if r.caused_by:
                body.append(style("muted", f"caused by: {r.caused_by}"))
            fix = "keep the access, or update the contract in the same PR with owner approval"
            body.append(f"{style('accent', '→')} {fix}")
        blocks.append((f"{style(sym_token, sym)} {r.address}", sym_token, body))

    if framed:
        frame = Frame(ascii_mode, style, width)
        lines = frame.open(title)
        lines += [frame.step(summary, info=True, token=token), frame.bar()]
        for head, sym_token, body in blocks:
            lines += frame.box(head, body, token=sym_token)
        done = {"PASS": "Done. Every change keeps its contracts."}
        lines += frame.close(done.get(state, "Stopped. Fix the change or the contract first."))
    else:
        lines = [title, "", summary]
        for head, _, body in blocks:
            sym, _, address = head.partition(" ")
            lines += ["", f"{sym} {style('bold', address)}"] + [f"  {x}" for x in body]
    text = "\n".join(lines) + "\n"
    return to_ascii(text) if ascii_mode else text
