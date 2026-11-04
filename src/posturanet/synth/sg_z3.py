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
        nested = solve_nested(needs, cands, quota)
        if nested is None:
            raise StageStop("fix", "the solver did not finish in time (result unknown)")
        return Synthesis(open_rules, kept, sorted(nested), needs, already, outside)
    model = opt.model()
    chosen = [c for u, c in zip(use, cands, strict=True) if z3.is_true(model.eval(u))]
    return Synthesis(open_rules, kept, sorted(chosen), needs, already, outside)


_INF = (float("inf"), 0)
Cost = tuple[float, int]  # (exposed addresses, rules), compared lexicographically
Plan = list[tuple[Cost, list[Rule]]]  # index k: best way to cover a subtree with <= k rules


def _merge(a: Plan, b: Plan, quota: int) -> Plan:
    out: Plan = [(_INF, []) for _ in range(quota + 1)]
    for i, (ca, ra) in enumerate(a):
        if ca == _INF:
            continue
        for j, (cb, rb) in enumerate(b[: quota + 1 - i]):
            if cb == _INF:
                continue
            cost = (ca[0] + cb[0], ca[1] + cb[1])
            if cost < out[i + j][0]:
                out[i + j] = (cost, ra + rb)
    for k in range(1, quota + 1):  # "<= k rules": carry the better smaller plan forward
        if out[k - 1][0] < out[k][0]:
            out[k] = out[k - 1]
    return out


def solve_nested(needs: list[Need], cands: list[Rule], quota: int) -> list[Rule] | None:
    """Same optimum as the Z3 model, for when Z3 runs out of time on many sources.

    Candidates with the same ports and protocol are prefixes, so any two are nested or
    disjoint. That makes them a forest, and the cheapest cover with at most `quota` rules is
    a knapsack over subtrees: each node is either chosen (covering all of its subtree) or
    left to its children. Returns None when no cover fits the quota.
    """
    empty: Plan = [((0, 0), [])] + [((0, 0), []) for _ in range(quota)]
    total = empty
    groups: dict[tuple[int, int, str], list[Rule]] = defaultdict(list)
    for c in cands:
        groups[(c.from_port, c.to_port, c.proto)].append(c)
    for _, members in sorted(groups.items()):
        members.sort(key=lambda r: (r.net.prefixlen, int(r.net.network_address)))
        parent: dict[Rule, Rule | None] = {}
        for i, c in enumerate(members):
            wider = [
                p for p in members[:i] if p.net.prefixlen < c.net.prefixlen and _contains(p, c)
            ]
            parent[c] = max(wider, key=lambda p: p.net.prefixlen) if wider else None
        children: dict[Rule | None, list[Rule]] = defaultdict(list)
        for c, p in parent.items():
            children[p].append(c)
        group_needs = [n for n in needs if any(c.admits(n.net, n.port, n.proto) for c in members)]
        # A need sits on the narrowest candidate that admits it: only it or an ancestor covers it.
        own: dict[Rule, int] = defaultdict(int)
        for n in group_needs:
            narrowest = max(
                (c for c in members if c.admits(n.net, n.port, n.proto)),
                key=lambda c: c.net.prefixlen,
            )
            own[narrowest] += 1
        for root in children[None]:
            sub = _subtree(root, children, own, quota)
            if sub is not None:
                total = _merge(total, sub, quota)
    best = total[quota]
    return None if best[0] == _INF else best[1]


def _subtree(
    node: Rule, children: dict[Rule | None, list[Rule]], own: dict[Rule, int], quota: int
) -> Plan | None:
    """Best covers of the needs under `node`, indexed by rule count; None when it has none."""
    below: Plan = [((0, 0), []) for _ in range(quota + 1)]
    any_need = own[node] > 0
    for ch in children[node]:
        sub = _subtree(ch, children, own, quota)
        if sub is not None:
            any_need = True
            below = _merge(below, sub, quota)
    if not any_need:
        return None
    take: Cost = (float(node.net.num_addresses), 1)
    out: Plan = [(_INF, [])] + [(take, [node]) for _ in range(quota)]
    if own[node] == 0:  # no need sits on this node, so its children alone may cover it
        out = [min(x, y, key=lambda t: t[0]) for x, y in zip(out, below, strict=True)]
    return out


def _contains(outer: Rule, inner: Rule) -> bool:
    return inner.net.version == outer.net.version and inner.net.subnet_of(outer.net)  # type: ignore[arg-type]
