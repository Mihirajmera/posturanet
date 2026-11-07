"""Small, conservative reads of IAM policy JSON for change checks (gate). Pure functions.

Model scope: action names, wildcards, effects and principals. Resources are read only to
tell `*` from narrower scopes; condition keys are not evaluated, except that a Deny whose only
condition is `aws:SecureTransport` is treated as a TLS-only rule.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

_ACCOUNT = re.compile(r"^\d{12}$")
_ARN_ACCOUNT = re.compile(r"^arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):")


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value] if isinstance(value, list) else []


def statements(doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not doc:
        return []
    st = doc.get("Statement")
    if isinstance(st, dict):
        return [st]
    return [s for s in st if isinstance(s, dict)] if isinstance(st, list) else []


def covers(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def conditional(st: dict[str, Any]) -> bool:
    return bool(st.get("Condition"))


def tls_only(st: dict[str, Any]) -> bool:
    cond = st.get("Condition")
    if not isinstance(cond, dict) or not cond:
        return False
    keys = {k.lower() for op in cond.values() if isinstance(op, dict) for k in op}
    return keys == {"aws:securetransport"}


def principals(st: dict[str, Any]) -> list[str] | None:
    """AWS principals of a statement; `["*"]` for everyone; None when it uses NotPrincipal."""
    if "NotPrincipal" in st:
        return None
    p = st.get("Principal")
    if p == "*":
        return ["*"]
    if isinstance(p, dict):
        return as_list(p.get("AWS")) or (["<service>"] if p else [])
    return []


def account_of(requester: str) -> str | None:
    if _ACCOUNT.match(requester):
        return requester
    m = _ARN_ACCOUNT.match(requester)
    return m.group(1) if m else None


def principal_matches(principal: str, requester: str) -> bool:
    """Does a policy principal name this requester (an ARN, or a role session ARN)?"""
    if principal == "*":
        return True
    acct = account_of(requester)
    if acct and principal in (acct, f"arn:aws:iam::{acct}:root"):
        return True
    if principal == requester:
        return True
    # arn:aws:sts::A:assumed-role/<role>/<session> is the role arn:aws:iam::A:role/<role>
    m = re.match(r"^arn:aws:sts::(\d{12}):assumed-role/([^/]+)/", requester)
    return bool(m and principal == f"arn:aws:iam::{m.group(1)}:role/{m.group(2)}")
