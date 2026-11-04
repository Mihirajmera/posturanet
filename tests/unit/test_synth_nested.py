from __future__ import annotations

import random
from datetime import date

import pytest

from posturanet.contracts import default_must_deny
from posturanet.errors import StageStop
from posturanet.models import BehaviorContract, Confidence, NetRule
from posturanet.models.config import SynthesisConfig
from posturanet.models.contract import ObservedMeta, ObservedWindow
from posturanet.synth.sg_rules import Rule
from posturanet.synth.sg_z3 import candidates, needs_for, solve_nested, synthesize
from posturanet.validate.invariants import check_contract


def contract(sources: list[tuple[str, int]], opens: list[Rule]) -> BehaviorContract:
    return BehaviorContract(
        resource="aws_security_group.x",
        observed=ObservedMeta(
            source="test",
            window=ObservedWindow(start=date(2026, 8, 1), end=date(2026, 10, 29), days=89),
            confidence=Confidence.HIGH,
        ),
        must_allow=[NetRule(cidr=c, port=p, proto="tcp") for c, p in sources],
        must_deny=default_must_deny(opens, {p for _, p in sources}),
    )


def cost(rules: list[Rule]) -> tuple[int, int]:
    return sum(r.net.num_addresses for r in rules), len(rules)


@pytest.mark.parametrize("seed", range(40))
def test_nested_solver_matches_z3(seed: int) -> None:
    rng = random.Random(seed)
    ports = rng.sample([22, 3389, 5432], rng.randint(1, 2))
    opens = [Rule("0.0.0.0/0", p, p, "tcp") for p in ports]
    pools = [f"10.{rng.randint(0, 3)}.{rng.randint(0, 3)}", "203.0.113", "198.51.100"]
    sources = sorted(
        {(f"{rng.choice(pools)}.{rng.randint(1, 254)}/32", rng.choice(ports)) for _ in range(12)}
    )
    cfg = SynthesisConfig(rules_quota=rng.randint(1, 8))
    c = contract(sources, opens)
    needs, _, _ = needs_for(c, opens, [])
    try:
        z3_rules = synthesize(c, opens, cfg).added
    except StageStop:
        z3_rules = None
    nested = solve_nested(needs, candidates(needs, c.must_deny, cfg), cfg.rules_quota)
    if z3_rules is None:
        assert nested is None
    else:
        assert nested is not None
        assert cost(nested) == cost(z3_rules)


def test_seventy_runners_fit_the_quota() -> None:
    opens = [Rule("0.0.0.0/0", 22, 22, "tcp")]
    c = contract([(f"10.0.50.{i}/32", 22) for i in range(10, 80)], opens)
    needs, _, _ = needs_for(c, opens, [])
    rules = solve_nested(needs, candidates(needs, c.must_deny, SynthesisConfig()), 60)
    assert rules is not None and len(rules) <= 60
    assert all(r.holds for r in check_contract(rules, c))
    assert all(r.net.prefixlen >= 25 for r in rules)  # merges neighbours, never widens to a /24
