"""Check a change to a contracted IAM policy (contract kind `iam`, FR-51, check_change).

BLOCK when the changed policy stops allowing a `must_allow` action, brings back a
`must_remove` wildcard, or is deleted. UNKNOWN when the policy can't be read as literals, or
when the only statements that would allow an action carry conditions PosturaNet doesn't
evaluate. Resources and condition keys are outside the model scope.
"""

from __future__ import annotations

from typing import Any

from posturanet.iamfix.evaluate import as_list, conditional, covers, statements
from posturanet.models.iam import IamContract


def judge(contract: IamContract, doc: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """(violations, unknowns, needles): needles locate each violation in the contract file."""
    draft = "" if contract.status == "approved" else " (draft contract)"
    sts = statements(doc)
    allows = [s for s in sts if s.get("Effect") == "Allow"]
    denies = [s for s in sts if s.get("Effect") == "Deny"]
    violations: list[str] = []
    needles: list[str] = []
    unknowns: list[str] = []
    if any("NotAction" in s for s in allows):
        unknowns.append("an Allow statement uses NotAction; PosturaNet can't judge it")

    for item in contract.must_allow:
        a = item.action
        denied = [
            s
            for s in denies
            if any(covers(p, a) for p in as_list(s.get("Action")))
            and "*" in as_list(s.get("Resource"))
        ]
        if any(not conditional(s) for s in denied):
            violations.append(f"breaks must_allow: {a} is denied{_who(item.owner)}{draft}")
            needles.append(a)
            continue
        granting = [s for s in allows if any(covers(p, a) for p in as_list(s.get("Action")))]
        if not granting:
            who = _who(item.owner)
            violations.append(f"breaks must_allow: {a} is no longer allowed{who}{draft}")
            needles.append(a)
        elif all(conditional(s) for s in granting) or denied:
            unknowns.append(f"{a} is allowed only under conditions PosturaNet doesn't evaluate")

    for wildcard in contract.must_remove:
        back = [
            p
            for s in allows
            for p in as_list(s.get("Action"))
            if p.lower() == wildcard.lower() or p == "*"
        ]
        if back:
            violations.append(f"breaks must_remove: {back[0]} is allowed again{draft}")
            needles.append(wildcard)
    return violations, sorted(dict.fromkeys(unknowns)), needles


def _who(owner: str | None) -> str:
    return f" ({owner})" if owner else ""
