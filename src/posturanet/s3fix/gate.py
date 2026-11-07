"""Check a change against an S3 contract (kind `s3_public`, FR-50, check_change).

The contract promises two things: the buckets stay non-public (`must_block`), and every
`must_keep` requester keeps access. A change BLOCKs when it turns any Block Public Access
setting off or deletes the block, when a bucket policy would make a contracted bucket public
(Block Public Access would also reject it at apply), when a policy Denies a `must_keep`
requester, or (with a plan) when a policy drops the grant a cross-account `must_keep`
requester had. Non-literal values and conditions PosturaNet doesn't evaluate are UNKNOWN.
"""

from __future__ import annotations

from typing import Any

from posturanet.iamfix.evaluate import (
    as_list,
    conditional,
    covers,
    principal_matches,
    principals,
    statements,
    tls_only,
)
from posturanet.models.s3 import S3Contract
from posturanet.s3fix import FLAG_NAMES

POLICY_TYPE = "aws_s3_bucket_policy"
BLOCK_TYPES = ("aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block")

# Access-log operations to the IAM action they need; anything else is checked as s3:*.
_OPS = {
    "REST.GET.OBJECT": "s3:GetObject",
    "REST.HEAD.OBJECT": "s3:GetObject",
    "REST.PUT.OBJECT": "s3:PutObject",
    "REST.POST.UPLOAD": "s3:PutObject",
    "REST.COPY.OBJECT": "s3:PutObject",
    "REST.DELETE.OBJECT": "s3:DeleteObject",
    "REST.GET.BUCKET": "s3:ListBucket",
}


def _draft(contract: S3Contract) -> str:
    return "" if contract.status == "approved" else " (draft contract)"


def judge_flags(contract: S3Contract, flags: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(violations, unknowns) for the planned or written Block Public Access settings."""
    violations, unknowns = [], []
    for flag in FLAG_NAMES:
        value = flags.get(flag)
        if value is True:
            continue
        if value == "<unknown>":
            unknowns.append(f"{flag} isn't known until apply")
            continue
        violations.append(
            f"breaks must_block: {flag} is off, so public access can come back{_draft(contract)}"
        )
    return violations, unknowns


def _needs(use_ops: list[str]) -> list[str]:
    return sorted({_OPS.get(op, "s3:*") for op in use_ops} or {"s3:*"})


def judge_policy(
    contract: S3Contract,
    bucket: str,
    after: dict[str, Any] | None,
    before: dict[str, Any] | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """(violations, unknowns, needles) for one bucket's planned or written policy.

    `before` is the current policy when a plan has it; without it, a cross-account requester
    with no grant in `after` is UNKNOWN (it may get in some other way).
    """
    draft = _draft(contract)
    violations: list[str] = []
    unknowns: list[str] = []
    needles: list[str] = []
    sts = statements(after)
    for s in sts:
        ps = principals(s)
        if s.get("Effect") == "Allow" and ps is not None and "*" in ps and not conditional(s):
            violations.append(
                f"breaks must_block: the {bucket} policy allows everyone (Principal *); "
                f"Block Public Access also rejects it{draft}"
            )
            needles.append("must_block")
            break

    for use in contract.must_keep:
        if use.kind in ("anonymous", "service", "unknown"):
            continue
        who = f"{use.requester}" + (f" ({use.owner})" if use.owner else "")
        needs = _needs(use.operations)
        for s in (x for x in sts if x.get("Effect") == "Deny"):
            ps = principals(s)
            if ps is None:
                unknowns.append(f"the {bucket} policy uses NotPrincipal; can't judge {who}")
                continue
            if not any(principal_matches(p, use.requester) for p in ps):
                continue
            acts = as_list(s.get("Action"))
            hit = [n for n in needs if any(covers(p, n) or covers(n, p) for p in acts)]
            if not hit or tls_only(s):  # a TLS-only rule: S3 clients use HTTPS
                continue
            if conditional(s):
                unknowns.append(f"a conditional Deny may cover {who}; conditions aren't evaluated")
                continue
            violations.append(f"breaks must_keep: {who} is denied {hit[0]} on {bucket}{draft}")
            needles.append(use.requester)

        if use.kind != "cross_account":
            continue
        if _granted(sts, use.requester, needs):
            continue
        if before is None:
            unknowns.append(f"{who} has no grant in the {bucket} policy; can't tell how it gets in")
        elif _granted(statements(before), use.requester, needs):
            violations.append(f"breaks must_keep: {who} loses its grant on {bucket}{draft}")
            needles.append(use.requester)
    return violations, sorted(dict.fromkeys(unknowns)), needles


def _granted(sts: list[dict[str, Any]], requester: str, needs: list[str]) -> bool:
    for s in sts:
        if s.get("Effect") != "Allow" or conditional(s):
            continue
        ps = principals(s) or []
        named = [p for p in ps if p != "*" and principal_matches(p, requester)]
        acts = as_list(s.get("Action"))
        if named and all(any(covers(p, n) for p in acts) for n in needs):
            return True
    return False
