"""Idempotency key and PR markers (FR-28)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from posturanet.models import BehaviorContract, VerifySpec

_KEY_MARKER = re.compile(r"<!-- posturanet:key=([0-9a-f]{64}) -->")
_VERIFY_MARKER = re.compile(r"<!-- posturanet:verify=([A-Za-z0-9+/=]+) -->")
_FINDING_MARKER = re.compile(r"<!-- posturanet:finding=([0-9a-f]{16}) -->")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def contract_sha(contract: BehaviorContract) -> str:
    """Hash of what the contract requires, not of counts or dates that change every run."""
    rules = {
        k: sorted((r.cidr, r.port, r.proto) for r in getattr(contract, k))
        for k in ("must_allow", "must_deny", "needs_review")
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


def verify_marker(spec: VerifySpec) -> str:
    """The post-merge verify spec, base64 JSON in an HTML comment (architecture doc 11)."""
    raw = spec.model_dump_json(exclude_defaults=False).encode("utf-8")
    return f"<!-- posturanet:verify={base64.b64encode(raw).decode('ascii')} -->"


def spec_in(body: str | None) -> VerifySpec | None:
    m = _VERIFY_MARKER.search(body or "")
    if not m:
        return None
    try:
        return VerifySpec.model_validate_json(base64.b64decode(m.group(1)))
    except (ValueError, binascii.Error):
        return None


def key_in(body: str | None) -> str | None:
    m = _KEY_MARKER.search(body or "")
    return m.group(1) if m else None


def finding_in(body: str | None) -> str | None:
    m = _FINDING_MARKER.search(body or "")
    return m.group(1) if m else None
