"""Plan-scope gate (FR-23, architecture doc 9).

The plan may change only the target, and only in place. Anything else fails the run.
"""

from __future__ import annotations

from typing import Any

from posturanet.models import Check, CheckResult
from posturanet.synth.sg_rules import Rule, rules_from_state


def resource_change(plan: dict[str, Any], address: str) -> dict[str, Any] | None:
    for rc in plan.get("resource_changes", []):
        if isinstance(rc, dict) and rc.get("address") == address:
            return dict(rc)
    return None


def check_scope(plan: dict[str, Any], target: str) -> Check:
    others: list[str] = []
    target_actions: list[str] | None = None
    for rc in plan.get("resource_changes", []):
        actions = list(rc.get("change", {}).get("actions", []))
        if actions in (["no-op"], ["read"]):
            continue
        if rc.get("address") == target:
            target_actions = actions
        else:
            others.append(f"{rc.get('address')} ({'/'.join(actions)})")

    if others:
        return Check(
            id="plan_scope",
            required=True,
            result=CheckResult.FAIL,
            detail="plan also changes " + ", ".join(sorted(others)),
        )
    if target_actions is None:
        return Check(
            id="plan_scope",
            required=True,
            result=CheckResult.FAIL,
            detail="plan does not change the target",
        )
    if target_actions != ["update"]:
        return Check(
            id="plan_scope",
            required=True,
            result=CheckResult.FAIL,
            detail=f"target would be {'/'.join(target_actions)}, not updated in place",
        )
    return Check(
        id="plan_scope",
        required=True,
        result=CheckResult.PASS,
        detail="1 to change, 0 to add, 0 to destroy; only the target",
    )


def planned_rules(rc: dict[str, Any], key: str = "after") -> list[Rule] | None:
    """Ingress rules from a plan change (`before` or `after`); None if unknown at plan time."""
    change = rc.get("change", {})
    if key == "after" and (change.get("after_unknown") or {}).get("ingress"):
        return None
    values = change.get(key) or {}
    ingress = values.get("ingress")
    if not isinstance(ingress, list):
        return None
    return rules_from_state(ingress)
