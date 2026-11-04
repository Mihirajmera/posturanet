"""IAM least privilege: replace wildcard actions with the actions in use (FR-51).

IAM.1 (`"*"`) and IAM.21 (`service:*`) on customer-managed `aws_iam_policy` resources. The
evidence is IAM action-level last-accessed data for the policy; the change edits only the
`Action` lists of the statements that hold a targeted wildcard.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from posturanet.configfix.hcl_attrs import Unsupported
from posturanet.errors import StageStop
from posturanet.iamfix.doc import (
    PolicyDoc,
    find_document,
    realign,
    render_actions,
    reparse,
)
from posturanet.iamfix.shrink import StatementChange, recheck, targeted
from posturanet.models import Check, CheckResult, Diff, FileChange
from posturanet.synth.hcl_render import unified_diff

CONTROLS = ("IAM.1", "IAM.21")
POLICY_TYPE = "aws_iam_policy"
_BY_HAND = "shrink the policy by hand; PosturaNet edits only literal policy documents"


def load_document(directory: Path, file: Path, line: int) -> PolicyDoc:
    try:
        return find_document(directory, file, line)
    except Unsupported as exc:
        raise StageStop("fix", str(exc), [_BY_HAND]) from exc


def apply_changes(doc: PolicyDoc, changes: list[StatementChange], repo: Path) -> Diff:
    text = doc.text
    for ch in sorted(changes, key=lambda c: -(c.statement.span or (0, 0))[0]):
        span, st = ch.statement.span, ch.statement
        assert span is not None
        one_line = render_actions(ch.after, st.indent, multiline=False)
        key_col = span[0] - (text.rfind("\n", 0, span[0]) + 1)
        multiline = doc.form == "heredoc" or len(ch.after) > 3 or key_col + len(one_line) > 100
        if doc.form == "heredoc" and len(ch.after) == 1:
            multiline = False
        new = render_actions(ch.after, st.indent, multiline=multiline)
        text = text[: span[0]] + new + text[span[1] :]
        if doc.form != "heredoc":
            c0, c1 = st.container
            text = realign(text, c0, c1 + len(new) - (span[1] - span[0]), st.indent)
    rel = doc.file.resolve().relative_to(repo.resolve()).as_posix()
    udiff = unified_diff(rel, doc.text, text)
    removed = sorted({p for c in changes for p in c.removed})
    kept = sum(len(c.after) for c in changes)
    content = text.replace("\n", "\r\n") if doc.crlf else text
    return Diff(
        target_address="",
        files=[FileChange(path=rel, unified_diff=udiff, new_content=content)],
        summary=f"{', '.join(removed)} → {kept} used action(s) in {len(changes)} statement(s)",
        rules_before=[a for c in changes for a in c.before],
        rules_after=[a for c in changes for a in c.after],
        generator=f"template:iam_least_privilege@1:{doc.form}",
        sha256=hashlib.sha256(udiff.encode("utf-8")).hexdigest(),
    )


def recheck_code(control: str, doc: PolicyDoc, new_text: str) -> Check:
    """Read the edited document again and re-run the control on it."""
    try:
        statements = reparse(doc, new_text.replace("\r\n", "\n"))
    except Unsupported as exc:
        return Check(id="recheck", required=True, result=CheckResult.FAIL, detail=str(exc))
    as_json: list[dict[str, object]] = [
        {
            "Sid": s.sid,
            "Effect": s.effect,
            "Action": s.actions or [],
            "Resource": s.resources,
        }
        for s in statements
    ]
    ok, detail = recheck(control, as_json)
    if ok and any(
        targeted(control, a) for s in statements if s.effect == "Allow" for a in s.actions or []
    ):
        ok, detail = False, f"{control} wildcard still in the edited code"
    return Check(
        id="recheck",
        required=True,
        result=CheckResult.PASS if ok else CheckResult.FAIL,
        detail=detail.replace("changed policy", "edited code"),
    )


__all__ = ["CONTROLS", "POLICY_TYPE", "apply_changes", "load_document", "recheck_code"]
