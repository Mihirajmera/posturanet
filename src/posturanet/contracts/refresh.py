"""Compare an approved contract with fresh evidence (FR-52). Pure: evidence in, proposal out.

- New real users the contract doesn't cover are proposed additions (`must_allow`, or
  `needs_review` where `fix` would put them there). Likely scanners stay out, as in `fix`.
- Entries not seen in the whole window are proposed removals: flagged in the file and in the
  PR, never removed. A rare job (a quarterly drill) is the known risk, so a person decides.
- Weak evidence (below `evidence.min_confidence_for_pr`, the same rule as `fix`) → UNKNOWN.

The proposed contract goes back to `status: draft`: merging it after review, with
`status: approved` and `approved_by` set, approves it like any other contract (US-2 AC3).
"""

from __future__ import annotations

import ipaddress
from datetime import date

from posturanet import __version__
from posturanet.contracts.builder import build_contract
from posturanet.contracts.store import dump_contract
from posturanet.evidence.confidence import at_least
from posturanet.iamfix import contract as iamcontract
from posturanet.iamfix.evaluate import covers
from posturanet.models import BehaviorContract, Confidence, NetRule, Observations
from posturanet.models.contract import ObservedMeta, ObservedWindow
from posturanet.models.iam import IamAllowed, IamContract, IamEvidence
from posturanet.models.living import ContractRefresh, RefreshChange
from posturanet.models.s3 import S3Contract, S3Evidence, S3Use
from posturanet.s3fix import contract as s3contract
from posturanet.synth.sg_rules import Rule

AnyContract = BehaviorContract | S3Contract | IamContract

_REOPENED = {"status": "draft", "approved_by": None, "approved_at": None}


def skipped_draft(contract: AnyContract, rel: str) -> ContractRefresh:
    return ContractRefresh(
        resource=contract.resource,
        contract_file=rel,
        kind=contract.kind,
        status="SKIPPED",
        reasons=["draft contract: refresh proposes updates to approved contracts only"],
    )


def _weak(
    contract: AnyContract, rel: str, conf: Confidence, minimum: Confidence, evidence: str
) -> ContractRefresh | None:
    if at_least(conf, minimum) and conf is not Confidence.NONE:
        return None
    return ContractRefresh(
        resource=contract.resource,
        contract_file=rel,
        kind=contract.kind,
        status="UNKNOWN",
        evidence=evidence,
        reasons=[
            f"confidence {conf.value}; needs {minimum.value} to propose changes "
            "(the same rule as fix)"
        ],
    )


def _result(
    contract: AnyContract,
    rel: str,
    evidence: str,
    additions: list[RefreshChange],
    removals: list[RefreshChange],
    proposed: str,
) -> ContractRefresh:
    changed = bool(additions or removals)
    return ContractRefresh(
        resource=contract.resource,
        contract_file=rel,
        kind=contract.kind,
        status="PROPOSED" if changed else "PASS",
        evidence=evidence,
        additions=additions,
        removals=removals,
        proposed=proposed if changed else None,
    )


# --- security groups (kind network)


def _label(r: NetRule) -> str:
    return f"{r.cidr} → {r.port}/{r.proto}"


def _covered(rule: NetRule, rules: list[NetRule]) -> bool:
    net = ipaddress.ip_network(rule.cidr, strict=False)
    return any(
        Rule(r.cidr, r.port, r.port, r.proto).admits(net, rule.port, rule.proto) for r in rules
    )


def network(
    contract: BehaviorContract, obs: Observations, rel: str, minimum: Confidence
) -> ContractRefresh:
    w = obs.window
    evidence = f"{obs.source.replace('_', ' ')} · {w.days} days · confidence {obs.confidence.value}"
    weak = _weak(contract, rel, obs.confidence, minimum, evidence)
    if weak is not None:
        return weak
    draft = build_contract(obs, [], account=contract.account, region=contract.region)
    kept = [*contract.must_allow, *contract.needs_review]
    new_allow = [r for r in draft.must_allow if not _covered(r, kept)]
    new_review = [r for r in draft.needs_review if not _covered(r, kept)]
    span = f"{w.start.date()}..{w.end.date()}"

    def unseen(r: NetRule) -> bool:
        rule = Rule(r.cidr, r.port, r.port, r.proto)
        return not any(
            rule.admits(ipaddress.ip_network(i.cidr), i.port, i.proto) for i in obs.items
        )

    flag = f"not seen {span}; delete only if retired"
    gone = {id(r) for r in kept if unseen(r)}

    def flagged(rules: list[NetRule]) -> list[NetRule]:
        out = []
        for r in rules:
            if id(r) in gone and flag not in (r.reason or ""):
                reason = f"{r.reason}; {flag}" if r.reason else flag
                r = r.model_copy(update={"reason": reason})
            out.append(r)
        return out

    additions = [
        RefreshChange(section=s, entry=_label(r), detail=f"{r.count or 0:,} conns · {r.period}")
        for s, rules in (("must_allow", new_allow), ("needs_review", new_review))
        for r in rules
    ]
    removals = [
        RefreshChange(
            section=s, entry=_label(r), detail=f"not seen in {w.days} days" + _owner(r.owner)
        )
        for s, rules in (
            ("must_allow", contract.must_allow),
            ("needs_review", contract.needs_review),
        )
        for r in rules
        if id(r) in gone
    ]
    proposed = contract.model_copy(
        update={
            **_REOPENED,
            "observed": draft.observed,
            "must_allow": [*flagged(contract.must_allow), *new_allow],
            "needs_review": [*flagged(contract.needs_review), *new_review],
            "generated_by": f"posturanet {__version__}",
        }
    )
    return _result(contract, rel, evidence, additions, removals, dump_contract(proposed))


def _owner(owner: str | None) -> str:
    return f" · owner {owner}" if owner else ""


# --- IAM policies (kind iam)


def iam(
    contract: IamContract, ev: IamEvidence, rel: str, minimum: Confidence, today: date
) -> ContractRefresh:
    evidence = (
        f"{ev.source.replace('_', ' ')} · policy age {ev.age_days} days · "
        f"confidence {ev.confidence.value}"
    )
    weak = _weak(contract, rel, ev.confidence, minimum, evidence)
    if weak is not None:
        return weak
    if ev.policy_arn != contract.policy_arn:
        return ContractRefresh(
            resource=contract.resource,
            contract_file=rel,
            kind=contract.kind,
            status="UNKNOWN",
            evidence=evidence,
            reasons=[f"evidence is for {ev.policy_arn}, the contract for {contract.policy_arn}"],
        )
    new = [u for u in ev.used() if not any(covers(a.action, u.action) for a in contract.must_allow)]
    # Only actions IAM tracks at action level can be called unused; the rest stay silent.
    tracked = {a.action.lower(): a for s in ev.services if s.action_level for a in s.actions}
    unused = [
        a
        for a in contract.must_allow
        if a.source == "last_accessed"
        and a.action.lower() in tracked
        and tracked[a.action.lower()].last_seen is None
    ]
    additions = [
        RefreshChange(section="must_allow", entry=u.action, detail=f"last used {u.last_seen}")
        for u in new
    ]
    removals = [
        RefreshChange(
            section="must_allow",
            entry=a.action,
            detail="not used in IAM's tracking period" + _owner(a.owner),
        )
        for a in unused
    ]
    notes = [
        f"{a.action}: not used in IAM's tracking period (to {today}); delete it from "
        "must_allow only if no job needs it"
        for a in unused
    ]
    proposed = contract.model_copy(
        update={
            **_REOPENED,
            "observed": ObservedMeta(
                source=ev.source,
                window=ObservedWindow(start=ev.created or today, end=today, days=ev.age_days),
                confidence=ev.confidence,
            ),
            "must_allow": sorted(
                [
                    *contract.must_allow,
                    *(IamAllowed(action=u.action, last_seen=u.last_seen) for u in new),
                ],
                key=lambda a: a.action.lower(),
            ),
            "needs_review": [
                *contract.needs_review,
                *(n for n in notes if n not in contract.needs_review),
            ],
            "generated_by": f"posturanet {__version__}",
        }
    )
    return _result(contract, rel, evidence, additions, removals, iamcontract.dump(proposed))


# --- S3 buckets (kind s3_public)


def s3(
    contract: S3Contract, ev: S3Evidence, rel: str, minimum: Confidence, today: date
) -> ContractRefresh:
    evidence = (
        f"{ev.source.replace('_', ' ')} · {ev.window_days} days · confidence {ev.confidence.value}"
    )
    base = {
        "resource": contract.resource,
        "contract_file": rel,
        "kind": contract.kind,
        "evidence": evidence,
    }
    if ev.window_days == 0:
        # A private bucket with ACLs disabled has its access logs left unread, as in fix.
        return ContractRefresh(
            **base,
            status="SKIPPED",
            reasons=[
                "no access logs read: the bucket isn't public and ACLs are disabled, so "
                "requesters can't be compared; must_keep stays as approved"
            ],
        )
    if ev.blockers:
        return ContractRefresh(
            **base,
            status="UNKNOWN",
            reasons=[*ev.blockers[:3], "run `posturanet contract check --live` for this bucket"],
        )
    weak = _weak(contract, rel, ev.confidence, minimum, evidence)
    if weak is not None:
        return weak
    keeps = [u for b in ev.buckets for u in b.keeps]
    review = [u for b in ev.buckets for u in b.needs_review]
    known = {u.requester for u in [*contract.must_keep, *contract.needs_review]}
    seen = {u.requester for u in [*keeps, *review, *(x for b in ev.buckets for x in b.breaks)]}
    new_keep = [u for u in keeps if u.requester not in known]
    new_review = [u for u in review if u.requester not in known]

    def detail(u: S3Use) -> str:
        return f"{u.count:,} requests · last {u.last_seen}"

    additions = [
        RefreshChange(section=s, entry=u.requester, detail=detail(u))
        for s, uses in (("must_keep", new_keep), ("needs_review", new_review))
        for u in uses
    ]
    removals = [
        RefreshChange(
            section="must_keep",
            entry=u.requester,
            detail=f"no requests in {ev.window_days} days" + _owner(u.owner),
        )
        for u in contract.must_keep
        if u.kind != "anonymous" and u.requester not in seen
    ]
    start = date.fromordinal(today.toordinal() - ev.window_days)
    proposed = contract.model_copy(
        update={
            **_REOPENED,
            "observed": ObservedMeta(
                source=ev.source,
                window=ObservedWindow(start=start, end=today, days=ev.window_days),
                confidence=ev.confidence,
            ),
            "must_keep": [*contract.must_keep, *new_keep],
            "needs_review": [*contract.needs_review, *new_review],
            "generated_by": f"posturanet {__version__}",
        }
    )
    # S3 entries have no free-text field: removals are listed in the PR and the CLI only.
    return _result(contract, rel, evidence, additions, removals, s3contract.dump(proposed))
