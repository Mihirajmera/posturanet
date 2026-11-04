"""Idempotency key and PR markers (FR-28)."""

from __future__ import annotations

import hashlib
import json
import re

from posturanet.models import BehaviorContract

_KEY_MARKER = re.compile(r"<!-- posturanet:key=([0-9a-f]{64}) -->")
_FINDING_MARKER = re.compile(r"<!-- posturanet:finding=([0-9a-f]{16}) -->")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def contract_sha(contract: BehaviorContract) -> str:
    """Hash of what the contract requires, not of counts or dates that change every run."""
    rules = {
        k: sorted((r.cidr, r.port, r.proto) for r in getattr(contract, k))
        for k in ("must_allow", "must_deny", "needs_review", "not_kept")
    }
    return _sha(
        json.dumps({"resource": contract.resource, **rules}, sort_keys=True, separators=(",", ":"))
    )


def idempotency_key(finding_id: str, contract: BehaviorContract, diff_sha: str) -> str:
    return _sha(finding_id + contract_sha(contract) + diff_sha)


def finding_tag(finding_id: str) -> str:
    return _sha(finding_id)[:16]


def markers(key: str, finding_id: str) -> str:
    return f"<!-- posturanet:key={key} -->\n<!-- posturanet:finding={finding_tag(finding_id)} -->"


def key_in(body: str | None) -> str | None:
    m = _KEY_MARKER.search(body or "")
    return m.group(1) if m else None


def finding_in(body: str | None) -> str | None:
    m = _FINDING_MARKER.search(body or "")
    return m.group(1) if m else None
