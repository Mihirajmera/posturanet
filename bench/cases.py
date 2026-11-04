"""Benchmark cases: synthetic security groups with known ground truth.

Every case says, independently of any tool, which sources must keep working (`legit`) and
which must not get in (`hostile`). Flow logs are generated from the sources' schedules, so a
legit source whose schedule never falls inside the log window is invisible to evidence, exactly
like a quarterly job in a real account. Addresses are RFC 1918 / RFC 5737 only.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Literal

Schedule = Literal["daily", "weekdays", "weekly", "monthly", "once", "every120", "never"]

END = datetime(2026, 10, 30, tzinfo=UTC)
WINDOW_DAYS = 90
PROBE = "192.0.2.250"  # a fresh internet address; must be blocked after every fix


@dataclass(frozen=True)
class Source:
    ip: str
    port: int
    schedule: Schedule
    legit: bool = True
    note: str = ""
    proto: str = "tcp"
    day: int = 0  # weekday for weekly, day of month for monthly, days-before-END for once/every120

    @property
    def bytes_per_flow(self) -> tuple[int, int]:
        # Real sessions move kilobytes per flow; scanner probes and banner grabs, a few hundred.
        return (8_000, 120_000) if self.legit else (60, 400)


@dataclass(frozen=True)
class OpenRule:
    cidr: str
    from_port: int
    to_port: int
    proto: str = "tcp"


@dataclass
class Case:
    id: str
    title: str
    why: str
    rules: list[OpenRule]
    sources: list[Source]
    log_days: int = WINDOW_DAYS  # how long flow logs have existed
    enis: bool = True  # False: no network interfaces have flow logs
    extra_probes: list[str] = field(default_factory=list)
    # Sources a human wrote into an approved contract before the run.
    approved: list[str] = field(default_factory=list)

    @property
    def ports(self) -> list[int]:
        return sorted({r.from_port for r in self.rules if r.cidr in ("0.0.0.0/0", "::/0")})


def _active_days(s: Source, start: date, end: date) -> list[date]:
    days: list[date] = []
    d = start
    while d < end:
        hit = {
            "daily": True,
            "weekdays": d.weekday() < 5,
            "weekly": d.weekday() == s.day,
            "monthly": d.day == s.day,
            "once": (end - d).days == s.day,
            "every120": ((end - d).days - s.day) % 120 == 0 and (end - d).days >= s.day,
            "never": False,
        }[s.schedule]
        if hit:
            days.append(d)
        d += timedelta(days=1)
    return days


def flows(case: Case) -> dict[str, object]:
    """VPC flow-log aggregate in PosturaNet's `--evidence-file` format."""
    rng = random.Random(case.id)
    start = END - timedelta(days=case.log_days)
    records: list[dict[str, str]] = []
    for s in case.sources if case.enis else []:
        for d in _active_days(s, start.date(), END.date()):
            for hour in sorted(rng.sample(range(24), rng.randint(1, 3))):
                ts = datetime(d.year, d.month, d.day, hour, tzinfo=UTC)
                n = rng.randint(2, 60)
                records.append(
                    {
                        "srcAddr": s.ip,
                        "dstPort": str(s.port),
                        "protocol": "6" if s.proto == "tcp" else s.proto,
                        "hour": ts.strftime("%Y-%m-%d %H:00:00.000"),
                        "n": str(n),
                        "bytes": str(n * rng.randint(*s.bytes_per_flow)),
                    }
                )
    return {
        "_comment": f"Synthetic benchmark case {case.id}. RFC 1918 / RFC 5737 addresses only.",
        "enis": ["eni-0b0b0b0b0b0b00001"] if case.enis else [],
        "window": {
            "from": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "to": END.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "missing_hours": [],
        "records": records,
    }


OPEN_22 = OpenRule("0.0.0.0/0", 22, 22)

CASES: list[Case] = [
    Case(
        "bastion-ci-vpn",
        "Bastion used by CI runners and the VPN",
        "The common case: a handful of private sources use SSH every day.",
        [OPEN_22],
        [
            Source("10.0.4.12", 22, "daily", note="CI runner"),
            Source("10.0.4.37", 22, "daily", note="CI runner"),
            Source("10.0.9.12", 22, "weekdays", note="VPN"),
        ],
    ),
    Case(
        "office-public-ip",
        "Engineers SSH in from the office's public IP",
        "The only legit source is on the internet, so 'private ranges only' cuts it off.",
        [OPEN_22],
        [Source("203.0.113.10", 22, "weekdays", note="office NAT")],
    ),
    Case(
        "unused-rule",
        "Nobody has used SSH in 90 days",
        "Full flow-log coverage and zero SSH traffic: removing the rule is the right fix.",
        [OPEN_22],
        [],
    ),
    Case(
        "monthly-patch-job",
        "A patch job connects on the 1st of each month",
        "Seen only 3 times in 90 days. A fix must keep it, and a careful one asks a human.",
        [OPEN_22],
        [
            Source("10.0.4.12", 22, "daily", note="CI runner"),
            Source("10.0.30.8", 22, "monthly", day=1, note="patch job"),
        ],
    ),
    Case(
        "quarterly-dr-drill",
        "A DR drill connects every 120 days, last time 100 days ago",
        "Invisible in a 90-day window. Evidence-based tools cannot see it; this tests honesty.",
        [OPEN_22],
        [
            Source("10.0.4.12", 22, "daily", note="CI runner"),
            Source("10.0.40.5", 22, "every120", day=100, note="DR drill"),
        ],
    ),
    Case(
        "quarterly-dr-drill-approved",
        "The same DR drill, after the team wrote it into the approved contract",
        "Flow logs still cannot see it. The contract remembers it, so the fix keeps it.",
        [OPEN_22],
        [
            Source("10.0.4.12", 22, "daily", note="CI runner"),
            Source("10.0.40.5", 22, "every120", day=100, note="DR drill"),
        ],
        approved=["10.0.4.12", "10.0.40.5"],
    ),
    Case(
        "scanner-noise",
        "Internet scanners hit the open port on a few days",
        "An open rule logs scanner traffic as ACCEPT. Allowing 'whatever connected' lets them in.",
        [OPEN_22],
        [
            Source("10.0.4.12", 22, "daily", note="CI runner"),
            Source("198.51.100.23", 22, "once", day=40, legit=False, note="scanner"),
            Source("198.51.100.77", 22, "once", day=12, legit=False, note="scanner"),
        ],
    ),
    Case(
        "persistent-scanner",
        "A scanner hits the open port every day",
        "Daily traffic from an internet address looks like real use in flow logs.",
        [OPEN_22],
        [
            Source("10.0.4.12", 22, "daily", note="CI runner"),
            Source("198.51.100.99", 22, "daily", legit=False, note="scanner"),
        ],
    ),
    Case(
        "logs-10-days",
        "Flow logs were enabled 10 days ago",
        "Too little history to know what uses the rule; a monthly job has not run yet.",
        [OPEN_22],
        [
            Source("10.0.4.12", 22, "daily", note="CI runner"),
            Source("10.0.30.8", 22, "monthly", day=1, note="patch job"),
        ],
        log_days=10,
    ),
    Case(
        "no-flow-logs",
        "Flow logs are off for this VPC",
        "No evidence at all. The right move is to stop and say so.",
        [OPEN_22],
        [Source("10.0.4.12", 22, "daily", note="CI runner")],
        enis=False,
    ),
    Case(
        "rdp-jump-host",
        "Windows jump host on RDP, used from VPN and an admin's home IP",
        "Same pattern on 3389, with a weekly public source.",
        [OpenRule("0.0.0.0/0", 3389, 3389)],
        [
            Source("10.0.9.12", 3389, "weekdays", note="VPN"),
            Source("203.0.113.55", 3389, "weekly", day=5, note="admin home IP"),
        ],
    ),
    Case(
        "postgres-open",
        "Postgres open to the world, used by app servers and a BI tool",
        "A database port with private app traffic plus one public SaaS source.",
        [OpenRule("0.0.0.0/0", 5432, 5432)],
        [
            Source("10.0.12.21", 5432, "daily", note="app server"),
            Source("10.0.12.22", 5432, "daily", note="app server"),
            Source("203.0.113.80", 5432, "daily", note="BI SaaS egress"),
        ],
    ),
    Case(
        "ci-fleet-70",
        "70 CI runners SSH in from one /24",
        "More sources than AWS's 60-rule quota: one rule per IP cannot be applied.",
        [OPEN_22],
        [Source(f"10.0.50.{i}", 22, "daily", note="CI runner") for i in range(10, 80)],
    ),
]
