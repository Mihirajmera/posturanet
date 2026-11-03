"""Contract invariants on a rule set (FR-24).

`allow-observed` is proved with Z3 over 32-bit addresses: for each contract source, there is
no address in it that the rules would refuse. `deny-*` checks are exact set checks on the
CIDRs. Results describe the modeled scope only (NFR-12).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import z3

from posturanet.models import BehaviorContract, NetRule
from posturanet.synth.sg_rules import Rule, norm_proto, overlaps

MODEL_SCOPE = (
    "Z3 models the target security group's ingress rules only. NACLs, routing, proxies "
    "and application behavior are out of scope."
)
_BROAD_PREFIX = 8


@dataclass(frozen=True)
class InvariantResult:
    id: str
    holds: bool
    method: str
    detail: str = ""


def _port_match(r: Rule, port: int, proto: str) -> bool:
    if r.proto == "-1":
        return True
    if r.proto != norm_proto(proto):
        return False
    if r.proto in ("icmp", "icmpv6") and r.from_port == -1:
        return True
    return r.from_port <= port <= r.to_port


def _allowed_formula(rules: list[Rule], addr: z3.BitVecRef, port: int, proto: str) -> z3.BoolRef:
    terms: list[z3.BoolRef] = []
    for r in rules:
        net = r.net
        if net.version != 4 or not _port_match(r, port, proto):
            continue
        mask = (0xFFFFFFFF << (32 - net.prefixlen)) & 0xFFFFFFFF
        terms.append((addr & mask) == int(net.network_address))
    return z3.Or(terms) if terms else z3.BoolVal(False)


def allow_holds(rules: list[Rule], src: NetRule) -> bool:
    net = ipaddress.ip_network(src.cidr, strict=False)
    if net.version != 4:
        return any(r.admits(net, src.port, src.proto) for r in rules)
    addr = z3.BitVec("addr", 32)
    mask = (0xFFFFFFFF << (32 - net.prefixlen)) & 0xFFFFFFFF
    s = z3.Solver()
    s.add((addr & mask) == int(net.network_address))
    s.add(z3.Not(_allowed_formula(rules, addr, src.port, src.proto)))
    return bool(s.check() == z3.unsat)


def deny_holds(rules: list[Rule], deny: NetRule) -> bool:
    dnet = ipaddress.ip_network(deny.cidr, strict=False)
    proto = norm_proto(deny.proto)
    for r in rules:
        if not _port_match(r, deny.port, proto):
            continue
        rnet = r.net
        if rnet.version != dnet.version:
            continue
        if dnet.prefixlen < _BROAD_PREFIX:
            if rnet.prefixlen < _BROAD_PREFIX:
                return False
        elif overlaps(rnet, dnet):
            return False
    return True


def check_contract(rules: list[Rule], contract: BehaviorContract) -> list[InvariantResult]:
    out: list[InvariantResult] = []
    sources = [*contract.must_allow, *contract.needs_review]
    broken = [s for s in sources if not allow_holds(rules, s)]
    out.append(
        InvariantResult(
            id="allow-observed",
            holds=not broken,
            method="z3",
            detail=(
                f"{len(sources)}/{len(sources)} contract sources stay allowed"
                if not broken
                else "would block " + ", ".join(f"{b.cidr} → {b.port}/{b.proto}" for b in broken)
            ),
        )
    )
    by_port: dict[int, list[NetRule]] = {}
    for d in contract.must_deny:
        by_port.setdefault(d.port, []).append(d)
    for port, denies in sorted(by_port.items()):
        failed = [d for d in denies if not deny_holds(rules, d)]
        out.append(
            InvariantResult(
                id=f"deny-internet-{port}",
                holds=not failed,
                method="static",
                detail="" if not failed else "still open to " + ", ".join(d.cidr for d in failed),
            )
        )
    return out
