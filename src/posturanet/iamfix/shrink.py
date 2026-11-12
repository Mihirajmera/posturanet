"""Replace wildcard actions with the actions actually used (FR-51). Pure functions.

IAM.1 targets `"*"` in Allow statements; IAM.21 targets `service:*`. Only the targeted
wildcards change. Explicit and partial-wildcard actions (`s3:Get*`), resources, conditions
and Deny statements are kept as they are.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from posturanet.iamfix.doc import Statement
from posturanet.models.iam import ApprovalItem

_SERVICE_WILDCARD = re.compile(r"^([a-z0-9-]+):\*$", re.IGNORECASE)

# Services whose CloudTrail data events (GetObject, Invoke, GetItem, ...) are not in IAM
# action-level last-accessed data. A wildcard on one of these is shrunk only after a human
# confirms the full action list in the contract (`reviewed_services`). Conservative list.
DATA_PLANE = frozenset(
    {
        "s3",
        "s3-object-lambda",
        "s3express",
        "lambda",
        "dynamodb",
        "kinesis",
        "sns",
        "sqs",
        "bedrock",
        "sagemaker",
        "glue",
        "cloudtrail",
        "managedblockchain",
    }
)

# Actions IAM last-accessed data never reports (AWS docs: iam:PassRole isn't tracked). Removing
# a wildcard that covers one would drop it as "unused" even when deployments rely on it, so the
# fix stops until a human keeps it (`must_allow`, source: human) or confirms the service's full
# action list (`reviewed_services`).
UNTRACKED = ("iam:PassRole",)


@dataclass
class ServiceUse:
    namespace: str
    accessed: bool  # service-level: any authenticated use in the tracking period
    action_level: bool  # IAM reports tracked actions for this service
    actions: set[str] = field(default_factory=set)  # "ns:Action" used, from tracked actions


@dataclass
class StatementChange:
    statement: Statement
    before: list[str]
    after: list[str]
    removed: list[str]  # the wildcard patterns replaced


@dataclass
class ShrinkResult:
    changes: list[StatementChange]
    blockers: list[str]
    unknown_services: list[str]  # accessed without action-level data
    approvable: list[ApprovalItem] = field(default_factory=list)  # blockers a person can clear

    @property
    def only_approvable(self) -> bool:
        """Every blocker is one a person can approve, so approving them all unblocks the fix."""
        return bool(self.blockers) and len(self.blockers) == len(self.approvable)


def targeted(control: str, action: str) -> bool:
    if control == "IAM.1":
        return action == "*"
    return bool(_SERVICE_WILDCARD.match(action))


def _covers(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def shrink(
    control: str,
    statements: list[Statement],
    usage: dict[str, ServiceUse],
    *,
    reviewed: frozenset[str] = frozenset(),
    extra: Iterable[str] = (),
) -> ShrinkResult:
    """`reviewed`: services a human confirmed in the contract; `extra`: actions they added."""
    extra_actions = sorted(set(extra))
    changes: list[StatementChange] = []
    blockers: list[str] = []
    unknown: set[str] = set()
    approvable: dict[tuple[str, str], ApprovalItem] = {}
    for st in statements:
        if st.effect != "Allow":
            continue
        name = f"statement {st.sid or st.index + 1}"
        if st.not_action:
            blockers.append(f"{name} uses NotAction; PosturaNet doesn't shrink it")
            continue
        if not st.actions or not any(targeted(control, a) for a in st.actions):
            continue
        kept = [a for a in st.actions if not targeted(control, a)]
        removed = [a for a in st.actions if targeted(control, a)]
        added: set[str] = set()
        for pattern in removed:
            ns = None if pattern == "*" else pattern.split(":", 1)[0].lower()
            services = [usage[ns]] if ns in usage else [] if ns else list(usage.values())
            for svc in services:
                if not svc.accessed:
                    continue
                if not svc.action_level:
                    unknown.add(svc.namespace)
                    blockers.append(
                        f"{svc.namespace} was used, but IAM has no action-level data for it; "
                        f"can't tell which {svc.namespace} actions to keep"
                    )
                    continue
                if svc.namespace in DATA_PLANE and svc.namespace not in reviewed:
                    approvable[("data_plane", svc.namespace)] = ApprovalItem(
                        kind="data_plane", name=svc.namespace, used=sorted(svc.actions)
                    )
                    blockers.append(
                        f"{svc.namespace} data actions (for example object or item reads) aren't "
                        "in last-accessed data; list them in the contract and add "
                        f"{svc.namespace} to reviewed_services"
                    )
                    continue
                added |= svc.actions
            added |= {a for a in extra_actions if _covers(pattern, a)}
        after = sorted(
            {*kept, *(a for a in added if not any(_covers(k, a) for k in kept))},
            key=str.lower,
        )
        for act in UNTRACKED:
            ns = act.split(":", 1)[0]
            if (
                any(_covers(p, act) for p in removed)
                and not any(_covers(a, act) for a in after)
                and ns not in reviewed
            ):
                approvable[("untracked", act)] = ApprovalItem(kind="untracked", name=act)
                blockers.append(
                    f"{act} isn't in last-accessed data, so PosturaNet can't tell if it's used; "
                    f"add it to must_allow (source: human) to keep it, or add {ns} to "
                    "reviewed_services to remove it"
                )
        if not after:
            blockers.append(f"{name} allowed nothing that was used; remove it by hand")
            continue
        changes.append(StatementChange(st, list(st.actions), after, removed))
    return ShrinkResult(
        changes, sorted(dict.fromkeys(blockers)), sorted(unknown), list(approvable.values())
    )


# --- re-check on policy JSON (plan or state) and invariants


def _list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value] if isinstance(value, list) else []


def recheck(control: str, statements: list[dict[str, object]]) -> tuple[bool, str]:
    bad = []
    for i, s in enumerate(statements):
        if s.get("Effect") != "Allow":
            continue
        actions = _list(s.get("Action"))
        if control == "IAM.1":
            if "*" in actions and "*" in _list(s.get("Resource")):
                bad.append(f"statement {s.get('Sid') or i + 1} allows * on *")
        else:
            hits = [a for a in actions if _SERVICE_WILDCARD.match(a)]
            if hits:
                bad.append(f"statement {s.get('Sid') or i + 1} allows {', '.join(hits)}")
    if bad:
        return False, f"{control} would still fail: " + "; ".join(bad)
    return True, f"{control} passes on the changed policy"


def check_invariants(
    changes: list[StatementChange], usage: dict[str, ServiceUse], extra: Iterable[str]
) -> list[str]:
    """Violations: the new policy must allow every used action the old statement allowed, and
    nothing the old statement didn't allow."""
    out = []
    extra_set = set(extra)
    for ch in changes:
        for a in ch.after:
            if not any(_covers(p, a) for p in ch.before):
                out.append(f"{a} wasn't allowed before")
        used = {a for svc in usage.values() for a in svc.actions} | extra_set
        for a in sorted(used):
            if any(_covers(p, a) for p in ch.removed) and not any(_covers(p, a) for p in ch.after):
                out.append(f"used action {a} is no longer allowed")
    return out
