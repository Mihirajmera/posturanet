"""Living contracts benchmark family (R11): does an approved contract stay true over time?

Two halves, both through the real code on a generated repo with the bastion contract approved:

- **Drift** (`contract check --live`): the deployed group is changed outside the code (a
  console edit, a prefix list, a lost permission). Ground truth is whether the live group
  still keeps the contract. Reporting PASS on a group that breaks it is **wrongly safe**.
- **Refresh** (`contract refresh`): usage changes after approval (a new internal user, a rare
  job that stops appearing, a scanner, too little history). Ground truth is what a careful
  reviewer would want proposed. Dropping an approved entry, approving a scanner, or proposing
  anything from weak evidence is **wrongly safe**.

Addresses are RFC 1918 / RFC 5737 only.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from fakes import FakeTerraform  # noqa: E402
from posturanet.contracts import load_contract, write_contract  # noqa: E402
from posturanet.evidence import FileSource  # noqa: E402
from posturanet.living import check_live, refresh  # noqa: E402
from posturanet.models import BehaviorContract  # noqa: E402
from posturanet.models.config import load_config  # noqa: E402
from posturanet.pipeline import Context, run_fix  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
REL = "posturanet/contracts/module.bastion.aws_security_group.this.yaml"
NOW = datetime(2026, 10, 29, tzinfo=UTC)
SG_ID = "sg-0a91f3c2"
KEPT = ["10.0.4.12/32", "10.0.4.37/32", "10.0.5.9/32", "203.0.113.7/32"]


@dataclass
class LivingResult:
    tool: str
    status: str  # PASS, BLOCK, UNKNOWN, PROPOSED
    expect: str  # the status a careful reviewer wants
    safe_ok: bool  # False: PosturaNet called something safe that isn't
    note: str = ""

    @property
    def verdict(self) -> str:
        if not self.safe_ok:
            return "WRONGLY SAFE"
        return "CORRECT" if self.status == self.expect else "MISS"


@dataclass
class DriftCase:
    cid: str
    title: str
    perms: list[dict[str, Any]] | None  # None: reading the group is denied
    expect: str


@dataclass
class RefreshCase:
    cid: str
    title: str
    edit: Callable[[dict[str, Any]], None]
    expect: str
    added: list[str]  # entries that must be proposed
    flagged: list[str]  # approved entries that must be flagged (and kept)


def _ssh(*cidrs: str, proto: str = "tcp", port: int = 22) -> dict[str, Any]:
    v4 = [c for c in cidrs if ":" not in c]
    v6 = [c for c in cidrs if ":" in c]
    return {
        "IpProtocol": proto,
        "FromPort": port,
        "ToPort": port,
        "IpRanges": [{"CidrIp": c} for c in v4],
        "Ipv6Ranges": [{"CidrIpv6": c} for c in v6],
    }


DRIFT = [
    DriftCase("drift-none", "Live group matches the code", [_ssh(*KEPT)], "PASS"),
    DriftCase(
        "drift-console-ssh",
        "Someone reopens 0.0.0.0/0 on port 22 in the console",
        [_ssh(*KEPT, "0.0.0.0/0")],
        "BLOCK",
    ),
    DriftCase(
        "drift-console-all-traffic",
        "Someone adds an all-traffic rule from 0.0.0.0/0",
        [_ssh(*KEPT), _ssh("0.0.0.0/0", proto="-1", port=-1)],
        "BLOCK",
    ),
    DriftCase(
        "drift-console-ipv6",
        "Someone opens port 22 to ::/0",
        [_ssh(*KEPT, "::/0")],
        "BLOCK",
    ),
    DriftCase(
        "drift-partner-removed",
        "The partner's address is removed by hand",
        [_ssh(*KEPT[:3])],
        "BLOCK",
    ),
    DriftCase(
        "drift-prefix-list",
        "A prefix-list source is added (it may hold 0.0.0.0/0)",
        [{**_ssh(*KEPT), "PrefixListIds": [{"PrefixListId": "pl-0a1b2c3d"}]}],
        "UNKNOWN",
    ),
    DriftCase("drift-read-denied", "The read-only role can't describe the group", None, "UNKNOWN"),
]


def _hours(data: dict[str, Any], src: str) -> list[dict[str, Any]]:
    return [r for r in data["records"] if r["srcAddr"] == src]


def _drop(src: str) -> Callable[[dict[str, Any]], None]:
    def edit(data: dict[str, Any]) -> None:
        data["records"] = [r for r in data["records"] if r["srcAddr"] != src]

    return edit


def _add(src: str, like: str, nbytes: int | None = None) -> Callable[[dict[str, Any]], None]:
    def edit(data: dict[str, Any]) -> None:
        extra = [{**r, "srcAddr": src} for r in _hours(data, like)]
        if nbytes is not None:
            extra = [{**r, "bytes": str(nbytes * int(r["n"]))} for r in extra]
        data["records"] += extra

    return edit


def _short(data: dict[str, Any]) -> None:
    data["window"]["from"] = "2026-10-22T00:00:00Z"
    data["records"] = [r for r in data["records"] if r["hour"] >= "2026-10-22"]
    data["missing_hours"] = []


REFRESH = [
    RefreshCase("refresh-none", "Usage hasn't changed", lambda d: None, "PASS", [], []),
    RefreshCase(
        "refresh-new-internal-user",
        "A new internal host starts using SSH every day",
        _add("10.0.6.20", like="10.0.4.12"),
        "PROPOSED",
        ["10.0.6.20/32 → 22/tcp"],
        [],
    ),
    RefreshCase(
        "refresh-source-stopped",
        "An approved host stops appearing (retired, or a job rarer than the window)",
        _drop("10.0.5.9"),
        "PROPOSED",
        [],
        ["10.0.5.9/32 → 22/tcp"],
    ),
    RefreshCase(
        "refresh-new-scanner",
        "An internet scanner starts probing port 22 (scan-sized flows)",
        _add("198.51.100.77", like="10.0.4.12", nbytes=120),
        "PASS",
        [],
        [],
    ),
    RefreshCase(
        "refresh-short-history",
        "Flow logs only cover the last week",
        _short,
        "UNKNOWN",
        [],
        [],
    ),
]


def _repo(work: Path) -> tuple[Path, BehaviorContract]:
    repo = work / "repo"
    shutil.copytree(FIX / "tf" / "basic", repo)
    config, _ = load_config(repo)
    ctx = Context(
        mode="check",
        evidence=FileSource(FIX / "flows" / "bastion_90d.json"),
        terraform=FakeTerraform(),
    )
    run_fix(str(FIX / "findings" / "sg_ssh_open.json"), repo, config, ctx)
    c = load_contract(repo / REL)
    assert c is not None
    c = c.model_copy(update={"status": "approved", "approved_by": "@bench"})
    write_contract(repo / REL, c)
    return repo, c


class _Denied(Exception):
    response = {"Error": {"Code": "UnauthorizedOperation"}}


def _aws(perms: list[dict[str, Any]] | None) -> Any:
    class Ec2:
        def describe_security_groups(self, GroupIds: list[str]) -> dict[str, Any]:  # noqa: N803
            if perms is None:
                raise _Denied()
            return {"SecurityGroups": [{"GroupId": SG_ID, "IpPermissions": perms}]}

    class Sts:
        def get_caller_identity(self) -> dict[str, str]:
            return {"Account": "123456789012"}

    clients = {"ec2": Ec2(), "sts": Sts()}
    return lambda service: clients[service]


def run_drift(case: DriftCase, repo: Path) -> LivingResult:
    config, _ = load_config(repo)
    result = check_live(repo, config, _aws(case.perms))
    status = result.status
    safe_ok = not (status == "PASS" and case.expect != "PASS")
    return LivingResult(
        "PosturaNet", status, case.expect, safe_ok, "; ".join(result.results[0].reasons)
    )


def run_refresh(
    case: RefreshCase, repo: Path, approved: BehaviorContract, work: Path
) -> LivingResult:
    from ruamel.yaml import YAML

    data = json.loads((FIX / "flows" / "bastion_90d.json").read_text(encoding="utf-8"))
    case.edit(data)
    flows = work / f"{case.cid}.json"
    flows.write_text(json.dumps(data), encoding="utf-8")
    config, _ = load_config(repo)
    [r] = refresh(repo, config, target=approved.resource, aws=None, evidence_file=flows, now=NOW)
    added = {a.entry for a in r.additions}
    flagged = {x.entry for x in r.removals}
    problems: list[str] = []
    if r.proposed is not None:
        if case.expect == "UNKNOWN":
            problems.append("proposed from weak evidence")
        new = BehaviorContract.model_validate(YAML(typ="safe").load(r.proposed))
        have = {(x.cidr, x.port, x.proto) for x in [*new.must_allow, *new.needs_review]}
        lost = [
            x
            for x in [*approved.must_allow, *approved.needs_review]
            if (x.cidr, x.port, x.proto) not in have
        ]
        problems += [f"dropped {x.cidr}:{x.port}" for x in lost]
        problems += [
            f"approved scanner {x.cidr}"
            for x in new.must_allow
            if x.cidr.startswith("198.51.100.77")
        ]
        if new.must_deny != approved.must_deny:
            problems.append("must_deny changed")
    missing = [e for e in case.added if e not in added] + [
        e for e in case.flagged if e not in flagged
    ]
    status = r.status if not missing else f"{r.status} (missed {', '.join(missing)})"
    note = "; ".join([*problems, *r.reasons]) or ", ".join(sorted(added | flagged))
    return LivingResult("PosturaNet", status, case.expect, not problems, note)


def run() -> dict[str, list[LivingResult]]:
    out: dict[str, list[LivingResult]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        repo, approved = _repo(work)
        for d in DRIFT:
            out[d.cid] = [run_drift(d, repo)]
        for c in REFRESH:
            out[c.cid] = [run_refresh(c, repo, approved, work)]
    return out


def wrongly_safe(results: dict[str, list[LivingResult]]) -> list[str]:
    return [cid for cid, outs in results.items() for o in outs if o.verdict == "WRONGLY SAFE"]


def report(results: dict[str, list[LivingResult]]) -> list[str]:
    titles = {c.cid: c.title for c in DRIFT} | {c.cid: c.title for c in REFRESH}
    correct = sum(o.verdict == "CORRECT" for outs in results.values() for o in outs)
    bad = wrongly_safe(results)
    lines = [
        "## Living contracts (drift and refresh)",
        "",
        "An approved security-group contract over time: the deployed group changed outside the "
        "code (`contract check --live`), and usage changed after approval (`contract refresh`). "
        "Wrongly safe means a PASS on a group that breaks its contract, or a proposal that drops "
        "an approved entry, approves a scanner, or comes from weak evidence. PosturaNet only.",
        "",
        f"{correct} of {len(results)} correct · {len(bad)} wrongly safe",
        "",
        "| Case | Expected | PosturaNet | Verdict | Detail |",
        "|---|---|---|---|---|",
    ]
    for cid, outs in results.items():
        for o in outs:
            detail = o.note.replace("|", "\\|")[:140] or "-"
            lines.append(
                f"| `{cid}`: {titles[cid]} | {o.expect} | {o.status} | {o.verdict.title()} | {detail} |"  # noqa: E501
            )
    return [*lines, ""]
