"""Publish the contract check as a GitHub check run (FR-29, US-4; design system section 7).

Writes only a check run on the given commit. Annotations point at the broken contract line
and at the security group's resource block.
"""

from __future__ import annotations

from typing import Any

from posturanet.deliver.github import GitHub
from posturanet.gate import GateResult

CHECK_NAME = "PosturaNet contract"
_CONCLUSION = {"PASS": "success", "BLOCK": "failure", "UNKNOWN": "neutral"}
_MAX_ANNOTATIONS = 50  # GitHub's limit per request
_NEXT = "→ keep the access, or update the contract in the same PR with owner approval"


def check_text(result: GateResult) -> str:
    lines: list[str] = []
    for r in result.results:
        if r.status == "PASS":
            lines.append(f"✓ {r.address}")
            continue
        sym = "✗" if r.status == "BLOCK" else "?"
        lines.append(f"{sym} {r.address}")
        lines += [f"  {reason}" for reason in r.reasons]
        if r.status == "BLOCK":
            if r.caused_by:
                lines.append(f"  caused by: {r.caused_by}")
            lines.append(f"  {_NEXT}")
    if not lines:
        lines.append("No security group with a contract is changed.")
    return "```text\n" + "\n".join(lines) + "\n```"


def check_summary(result: GateResult) -> str:
    out = [result.summary, ""]
    if result.status == "UNKNOWN":
        out.append(
            "PosturaNet could not judge every contracted group, so this check is not green. "
            "Review the groups marked ? by hand."
        )
    if result.mode == "source":
        out.append("Checked from the Terraform source (no plan). Literal ingress blocks only.")
    return "\n".join(out).strip()


def check_annotations(result: GateResult) -> list[dict[str, Any]]:
    notes: list[dict[str, Any]] = []
    for r in result.results:
        if r.status == "PASS":
            continue
        level = "failure" if r.status == "BLOCK" else "warning"
        for v in r.violations:
            notes.append(
                {
                    "path": r.contract_file,
                    "start_line": v.contract_line or 1,
                    "end_line": v.contract_line or 1,
                    "annotation_level": level,
                    "title": f"{CHECK_NAME}: {r.address}",
                    "message": v.message,
                }
            )
        if r.source_file and r.source_line:
            notes.append(
                {
                    "path": r.source_file,
                    "start_line": r.source_line,
                    "end_line": r.source_line,
                    "annotation_level": level,
                    "title": f"{CHECK_NAME}: {r.status}",
                    "message": "; ".join(r.reasons) or r.status,
                }
            )
    return notes[:_MAX_ANNOTATIONS]


def payload(result: GateResult, head_sha: str) -> dict[str, Any]:
    return {
        "name": CHECK_NAME,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": _CONCLUSION[result.status],
        "output": {
            "title": result.summary,
            "summary": check_summary(result),
            "text": check_text(result),
            "annotations": check_annotations(result),
        },
    }


def publish(gh: GitHub, result: GateResult, head_sha: str) -> str:
    data = gh.create_check_run(payload(result, head_sha))
    return str(data.get("html_url", ""))


COMMENT_MARKER = "<!-- posturanet:contract-check -->"
_HEADLINE = {
    "PASS": "✓ PosturaNet contract check passed",
    "BLOCK": "✗ PosturaNet contract check: this change breaks a contract",
    "UNKNOWN": "? PosturaNet contract check: needs a person to review",
}


def comment_body(result: GateResult, check_url: str | None = None) -> str:
    lines = [COMMENT_MARKER, f"### {_HEADLINE[result.status]}", "", check_summary(result), ""]
    lines.append(check_text(result))
    if check_url:
        lines += ["", f"[Annotated lines in the check run]({check_url})"]
    lines += [
        "",
        "<sub>Contracts list the access each resource must keep, from observed usage. "
        "[PosturaNet](https://posturanet.com) · read-only · a person merges.</sub>",
    ]
    return "\n".join(lines)


def comment(gh: GitHub, result: GateResult, pr: int, check_url: str | None = None) -> str | None:
    """One sticky comment per PR. A PASS only edits an existing comment, so green PRs stay quiet."""
    body = comment_body(result, check_url)
    return gh.upsert_comment(pr, COMMENT_MARKER, body, create=result.status != "PASS")
