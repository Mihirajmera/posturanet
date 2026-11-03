"""Minimal SG ingress rule synthesis with Z3 (FR-18, architecture doc 8.1).

Only the open (in-scope) rules are replaced. Traffic already allowed by the rules that stay
is not re-covered. The solver picks, from observed sources and their supernets up to the
configured prefix limit, the rule set that keeps every contract source allowed, never
widens to a `must_deny` network, fits the quota, and exposes the fewest addresses.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass

import z3

from posturanet.errors import StageStop
from posturanet.models import BehaviorContract, NetRule
from posturanet.models.config import SynthesisConfig
from posturanet.synth.sg_rules import Net, Rule, is_internal, norm_proto, overlaps

_BROAD_PREFIX = 8  # a must_deny wider than this means "never contain it"; narrower: never overlap
_TIMEOUT_MS = 30_000


@dataclass(frozen=True)
class Need:
    net: Net
    port: int
    proto: str
    source: NetRule


@dataclass
class Synthesis:
    removed: list[Rule]
    kept: list[Rule]
    added: list[Rule]
    covered: list[Need]  # contract sources the new rules keep allowed
    already_allowed: list[NetRule]  # contract sources the kept rules already allow
    out_of_scope: list[NetRule]  # contract sources the open rules never allowed


def needs_for(
    contract: BehaviorContract, open_rules: list[Rule], kept: list[Rule]
) -> tuple[list[Need], list[NetRule], list[NetRule]]:
    needs: list[Need] = []
    already: list[NetRule] = []
    outside: list[NetRule] = []
    for src in [*contract.must_allow, *contract.needs_review]:
        net = ipaddress.ip_network(src.cidr, strict=False)
        proto = norm_proto(src.proto)
        if any(r.admits(net, src.port, proto) for r in kept):
            already.append(src)
        elif any(r.admits(net, src.port, proto) for r in open_rules):
            needs.append(Need(net, src.port, proto, src))
        else:
            outside.append(src)
    return needs, already, outside


def _max_prefix(net: Net, cfg: SynthesisConfig) -> int:
    if net.version == 6:
        return net.prefixlen  # IPv6 never reaches here in R1; keep exact
    return cfg.max_prefix_private if is_internal(net) else cfg.max_prefix_public


def _denied(cand: Net, port: int, proto: str, deny: list[NetRule]) -> bool:
    for d in deny:
        if d.port != port or norm_proto(d.proto) not in (proto, "-1"):
            continue
        dnet = ipaddress.ip_network(d.cidr, strict=False)
        if dnet.version != cand.version:
            continue
        if dnet.prefixlen < _BROAD_PREFIX:
            if dnet.subnet_of(cand):  # type: ignore[arg-type]
                return True
        elif overlaps(cand, dnet):
            return True
    return False


def candidates(needs: list[Need], deny: list[NetRule], cfg: SynthesisConfig) -> list[Rule]:
    out: set[Rule] = set()
    for n in needs:
        port_lo, port_hi = (-1, -1) if n.proto in ("icmp", "icmpv6") else (n.port, n.port)
        limit = _max_prefix(n.net, cfg)
        for plen in range(n.net.prefixlen, min(limit, n.net.prefixlen) - 1, -1):
            cand = n.net.supernet(new_prefix=plen) if plen < n.net.prefixlen else n.net
            if _denied(cand, n.port, n.proto, deny):
                break  # wider supernets contain this one, so they are denied too
            out.add(Rule(str(cand), port_lo, port_hi, n.proto))
    return sorted(out)


def synthesize(
    contract: BehaviorContract,
    current: list[Rule],
    cfg: SynthesisConfig,
) -> Synthesis:
    open_rules = [r for r in current if r.is_world]
    kept = [r for r in current if not r.is_world]
    needs, already, outside = needs_for(contract, open_rules, kept)

    v6 = [n for n in needs if n.net.version == 6]
    if v6:
        raise StageStop(
            "fix",
            f"observed IPv6 sources need the open rule ({v6[0].net}); IPv6 synthesis is not in R1",
            ["fix this group by hand, or keep the IPv6 rule and re-run for IPv4"],
        )

    quota = cfg.rules_quota - len(kept)
    if not needs:
        return Synthesis(open_rules, kept, [], [], already, outside)
    if quota <= 0:
        raise StageStop(
            "fix",
            f"no rule quota left: {len(kept)} rules stay and the quota is {cfg.rules_quota}",
            ["raise synthesis.rules_quota if your account limit is higher"],
        )

    cands = candidates(needs, contract.must_deny, cfg)
    use = [z3.Bool(f"use_{i}") for i in range(len(cands))]
    opt = z3.Optimize()
    opt.set("timeout", _TIMEOUT_MS)
    covering: dict[int, list[int]] = defaultdict(list)
    for ni, n in enumerate(needs):
        for ci, c in enumerate(cands):
            if c.admits(n.net, n.port, n.proto):
                covering[ni].append(ci)
        if not covering[ni]:
            raise StageStop(
                "fix",
                f"{n.net} → {n.port}/{n.proto} needs a rule that would violate must_deny",
                ["check must_deny in the contract, or remove that source if it is not needed"],
            )
        opt.add(z3.Or([use[ci] for ci in covering[ni]]))
    opt.add(z3.Sum([z3.If(u, 1, 0) for u in use]) <= quota)
    # Lexicographic: fewest exposed addresses first, then fewest rules.
    opt.minimize(
        z3.Sum([z3.If(u, c.net.num_addresses, 0) for u, c in zip(use, cands, strict=True)])
    )
    opt.minimize(z3.Sum([z3.If(u, 1, 0) for u in use]))

    result = opt.check()
    if result == z3.unsat:
        raise StageStop(
            "fix",
            f"no rule set covers {len(needs)} observed sources within the quota of {quota}",
            ["raise synthesis.max_prefix_* or synthesis.rules_quota, or fix by hand"],
        )
    if result != z3.sat:
        raise StageStop("fix", "the solver did not finish in time (result unknown)")
    model = opt.model()
    chosen = [c for u, c in zip(use, cands, strict=True) if z3.is_true(model.eval(u))]
    return Synthesis(open_rules, kept, sorted(chosen), needs, already, outside)
