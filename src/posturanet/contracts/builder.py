"""Observations -> draft BehaviorContract (FR-14)."""

from __future__ import annotations

from posturanet import __version__
from posturanet.contracts.invariants import SG_SENSITIVE_PORTS, WORLD_CIDRS
from posturanet.evidence.periodicity import describe
from posturanet.models import BehaviorContract, NetRule, Observations
from posturanet.models.contract import ObservedMeta, ObservedWindow
from posturanet.synth.sg_rules import Rule


def default_must_deny(open_rules: list[Rule], observed_ports: set[int]) -> list[NetRule]:
    """No world access on any sensitive port the open rules expose, nor on their single ports."""
    ports: set[int] = set()
    for r in open_rules:
        if r.proto == "-1":
            ports.update(SG_SENSITIVE_PORTS)
            ports.update(observed_ports)
            continue
        if r.from_port == r.to_port and r.from_port >= 0:
            ports.add(r.from_port)
        ports.update(p for p in SG_SENSITIVE_PORTS if r.from_port <= p <= r.to_port)
        ports.update(p for p in observed_ports if r.from_port <= p <= r.to_port)
    return [NetRule(cidr=c, port=p, proto="tcp") for p in sorted(ports) for c in WORLD_CIDRS]


def build_contract(
    obs: Observations,
    open_rules: list[Rule],
    *,
    account: str | None,
    region: str | None,
) -> BehaviorContract:
    allow: list[NetRule] = []
    review: list[NetRule] = []
    for item in obs.items:
        rule = NetRule(
            cidr=item.cidr,
            port=item.port,
            proto=item.proto,
            period=describe(item.period, item.hours_histogram),
            count=item.count,
        )
        (review if item.needs_review else allow).append(rule)

    return BehaviorContract(
        resource=obs.resource_address,
        account=account,
        region=region,
        observed=ObservedMeta(
            source=obs.source,
            window=ObservedWindow(
                start=obs.window.start.date(), end=obs.window.end.date(), days=obs.window.days
            ),
            confidence=obs.confidence,
        ),
        must_allow=allow,
        must_deny=default_must_deny(open_rules, {i.port for i in obs.items}),
        needs_review=review,
        unknown_risk=f"behavior rarer than once per {obs.window.days} days is not observed",
        generated_by=f"posturanet {__version__}",
    )
