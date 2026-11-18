"""Opt-in outcome share (FR-45a, AGENTS.md golden rule 6): did a fix hold or get reverted?

Off by default. When `outcome_share.enabled` is set, `posturanet verify` sends one
`SharedOutcome` per finished verify and nothing else. `posturanet outcomes preview` prints the
same records without sending them. Sending is best-effort: it never changes an exit code.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from posturanet.models import OutcomeState, RunRecord
from posturanet.models.common import FixType

TIMEOUT_S = 5.0
# Security Hub style ids only (EC2.19, RDS.8): anything else could carry a customer's name.
_CONTROL = re.compile(r"[A-Za-z][A-Za-z0-9]{0,23}\.[0-9]{1,4}")
_FIX_TYPES = {t.value for t in FixType if t is not FixType.UNSUPPORTED}


class SharedOutcome(BaseModel):
    """Everything that leaves the customer. Adding a field here widens golden rule 6."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    control: str = Field(pattern=_CONTROL.pattern)
    fix_type: str
    outcome: Literal["held", "reverted"]
    evidence_days: int = Field(ge=0)
    agent_version: str


def record_for(run: RunRecord) -> tuple[SharedOutcome | None, str]:
    """The record a verify run would share, or None and why not."""
    o = run.outcome
    if run.command != "verify" or o is None:
        return None, "not a verify run"
    if o.state is OutcomeState.CONFIRMED:
        verdict: Literal["held", "reverted"] = "held"
    elif o.state in (OutcomeState.REGRESSED, OutcomeState.REVERTED):
        verdict = "reverted"
    else:
        return None, f"{o.state.value}: shared once the fix is confirmed or regressed"
    if not _CONTROL.fullmatch(o.control):
        return None, "control id is not in the SERVICE.N form"
    if o.fix_type not in _FIX_TYPES:
        return None, "no fix type on this verify run (run by an older PosturaNet)"
    days = 0
    if o.watch_from is not None and o.watch_until is not None:
        # whole days of post-apply watching behind the verdict; 0 for unwatched fixes
        end = min(run.started_at, o.watch_until)
        days = max(0, (end - o.watch_from).days)
    rec = SharedOutcome(
        control=o.control,
        fix_type=str(o.fix_type),
        outcome=verdict,
        evidence_days=days,
        agent_version=run.agent_version,
    )
    return rec, "would be sent"


Post = Callable[[str, bytes], None]


def _https_post(url: str, body: bytes) -> None:
    resp = httpx.post(
        url,
        content=body,
        headers={"content-type": "application/json"},
        timeout=TIMEOUT_S,
        follow_redirects=False,
    )
    resp.raise_for_status()


def share(run: RunRecord, endpoint: str, post: Post = _https_post) -> str | None:
    """Send the run's record. Returns a warning, never raises: the pipeline must not care."""
    rec, _ = record_for(run)
    if rec is None:
        return None
    try:
        post(endpoint, rec.model_dump_json().encode("utf-8"))
    except Exception as exc:  # best-effort: timeout, DNS, TLS, HTTP status, anything
        return f"outcome share not sent ({type(exc).__name__}); verify result unchanged"
    return None


__all__ = ["SharedOutcome", "record_for", "share"]
