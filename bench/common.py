"""Scoring shared by the S3 and IAM benchmark families.

Each case states its ground truth before any tool runs: what the workload really needs, and
whether a safe fix exists (`expect`). A tool either changes the resource (FIXED) or declines
with a reason (STOPPED). A fix that takes away something the workload needs is an OUTAGE; one
that leaves the finding's exposure in place is STILL EXPOSED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Expect = Literal["fix", "stop"]
VERDICTS = ("CORRECT", "STOPPED", "OUTAGE", "STILL EXPOSED")


@dataclass
class Result:
    tool: str
    status: str  # FIXED or STOPPED
    expect: Expect
    broken: list[str] = field(default_factory=list)  # needs the fix takes away
    exposed: list[str] = field(default_factory=list)  # exposure the fix leaves
    allowed: list[str] = field(default_factory=list)  # what the fix leaves allowed
    note: str = ""

    @property
    def verdict(self) -> str:
        if self.status != "FIXED":
            return "STOPPED"
        if self.broken:
            return "OUTAGE"
        if self.exposed:
            return "STILL EXPOSED"
        return "CORRECT"


def summary(title: str, results: dict[str, list[Result]]) -> list[str]:
    tools = [r.tool for r in next(iter(results.values()))]
    head = [*(v.title() for v in VERDICTS), "Unneeded stops"]
    lines = [
        f"| {title} | " + " | ".join(head) + " |",
        "|---|" + "---|" * len(head),
    ]
    for i, tool in enumerate(tools):
        outs = [rs[i] for rs in results.values()]
        counts = [sum(1 for o in outs if o.verdict == v) for v in VERDICTS]
        unneeded = sum(1 for o in outs if o.verdict == "STOPPED" and o.expect == "fix")
        lines.append(f"| {tool} | " + " | ".join(map(str, [*counts, unneeded])) + " |")
    return lines


def per_case(
    cases: list[tuple[str, str, str, Expect]], results: dict[str, list[Result]]
) -> list[str]:
    lines: list[str] = []
    for cid, title, why, expect in cases:
        safe = (
            "a safe fix exists" if expect == "fix" else "no safe automatic fix: stopping is right"
        )
        lines += [
            f"#### `{cid}`: {title}",
            "",
            f"{why} Ground truth: {safe}.",
            "",
            "| Contender | Verdict | Detail |",
            "|---|---|---|",
        ]
        for o in results[cid]:
            detail = "; ".join(
                x
                for x in [
                    ("breaks " + ", ".join(o.broken)) if o.broken else "",
                    ("leaves " + ", ".join(o.exposed)) if o.exposed else "",
                    ("allows " + ", ".join(o.allowed)) if o.allowed and o.status == "FIXED" else "",
                    o.note if o.status != "FIXED" else "",
                ]
                if x
            )
            lines.append(f"| {o.tool} | {o.verdict.title()} | {detail or '-'} |")
        lines.append("")
    return lines
