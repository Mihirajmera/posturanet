"""Re-check the original finding on a rule set (FR-25).

Pure functions over rules, so the same check runs on the planned config and, after merge,
on live state. Semantics follow the AWS Security Hub control definitions.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from posturanet.synth.sg_rules import Rule

# Adapted from postura-backend/app/aws/discovery/checks.py (EC2.19 high-risk port list).
EC2_19_PORTS = (
    20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389,
    4333, 5000, 5432, 5500, 5601, 8080, 8088, 8888, 9200, 9300,
)  # fmt: skip
EC2_18_AUTHORIZED = (80, 443)


def _open(rules: Iterable[Rule], cidrs: tuple[str, ...]) -> list[Rule]:
    return [r for r in rules if r.cidr in cidrs]


def _exposes(r: Rule, port: int) -> bool:
    if r.proto == "-1":
        return True
    if r.proto not in ("tcp", "udp"):
        return False
    return r.from_port <= port <= r.to_port


def _ports(rules: list[Rule], ports: Iterable[int], cidrs: tuple[str, ...]) -> list[str]:
    bad = []
    for r in _open(rules, cidrs):
        hit = [p for p in ports if _exposes(r, p)]
        if hit:
            bad.append(f"{r.cidr} on {', '.join(str(p) for p in hit[:5])}")
    return bad


def _unrestricted(rules: list[Rule]) -> list[str]:
    bad = []
    for r in _open(rules, ("0.0.0.0/0", "::/0")):
        if r.proto in ("tcp",) and r.from_port == r.to_port and r.from_port in EC2_18_AUTHORIZED:
            continue
        bad.append(r.label())
    return bad


_CHECKS: dict[str, Callable[[list[Rule]], list[str]]] = {
    "EC2.13": lambda rs: _ports(rs, (22,), ("0.0.0.0/0",)),
    "EC2.14": lambda rs: _ports(rs, (3389,), ("0.0.0.0/0",)),
    "EC2.53": lambda rs: _ports(rs, (22, 3389), ("0.0.0.0/0",)),
    "EC2.54": lambda rs: _ports(rs, (22, 3389), ("::/0",)),
    "EC2.19": lambda rs: _ports(rs, EC2_19_PORTS, ("0.0.0.0/0", "::/0")),
    "EC2.18": _unrestricted,
    "manual": _unrestricted,
}


def supported(control_id: str) -> bool:
    return control_id in _CHECKS


def recheck(control_id: str, rules: list[Rule]) -> tuple[bool, str]:
    """(passes, detail). Raises KeyError for controls without a re-check."""
    failures = _CHECKS[control_id](rules)
    if failures:
        return False, f"{control_id} would still fail: {'; '.join(failures)}"
    return True, f"{control_id} passes on the planned config"
