"""Run every benchmark case through PosturaNet and the baselines, score, and write the report.

PosturaNet runs through its real pipeline (`run_fix_full`, check mode) on a generated repo.
Terraform is the provider-less double from the test suite: it plans by parsing the patched
HCL, which is all this benchmark needs, since it scores network behavior, not provider plans.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from bench.cases import CASES, END, PROBE, WINDOW_DAYS, Case, flows  # noqa: E402
from fakes import FakeTerraform, ingress_json  # noqa: E402
from posturanet.contracts import contract_path, default_must_deny, write_contract  # noqa: E402
from posturanet.evidence import FileSource  # noqa: E402
from posturanet.models import BehaviorContract, Confidence, NetRule  # noqa: E402
from posturanet.models.config import load_config  # noqa: E402
from posturanet.models.contract import ObservedMeta, ObservedWindow  # noqa: E402
from posturanet.pipeline import Context, run_fix_full  # noqa: E402
from posturanet.synth.sg_rules import Rule, is_internal  # noqa: E402

BASIC = ROOT / "tests" / "fixtures" / "tf" / "basic"
FINDING = ROOT / "tests" / "fixtures" / "findings" / "sg_ssh_open.json"
ADDRESS = "module.bastion.aws_security_group.this"
QUOTA = 60  # AWS default rules per security group
PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


@dataclass
class Outcome:
    tool: str
    status: str  # FIXED, STOPPED, INVALID
    rules: list[str] = field(default_factory=list)
    broken: list[str] = field(default_factory=list)  # legit sources the fix blocks
    exposed: list[str] = field(default_factory=list)  # hostile sources the fix still allows
    internet_addresses: int = 0  # public addresses allowed on the finding's ports
    total_addresses: int = 0  # all addresses allowed on the finding's ports
    flagged: list[str] = field(default_factory=list)  # sources PosturaNet asked a human about
    note: str = ""

    @property
    def verdict(self) -> str:
        if self.status != "FIXED":
            return self.status
        if self.broken:
            return "OUTAGE"
        if self.exposed:
            return "STILL EXPOSED"
        return "CORRECT"


def _rules(case: Case) -> list[Rule]:
    return [Rule(r.cidr, r.from_port, r.to_port, r.proto) for r in case.rules]


def _hcl(rules: list[Rule]) -> str:
    blocks = []
    for r in rules:
        blocks.append(
            "  ingress {\n"
            f"    from_port   = {r.from_port}\n"
            f"    to_port     = {r.to_port}\n"
            f'    protocol    = "{r.proto}"\n'
            f'    cidr_blocks = ["{r.cidr}"]\n'
            "  }\n"
        )
    return (
        'variable "vpc_id" {\n  type = string\n}\n\n'
        'resource "aws_security_group" "this" {\n'
        '  name   = "bench"\n'
        "  vpc_id = var.vpc_id\n\n" + "\n".join(blocks) + "}\n"
    )


def _repo(case: Case, work: Path) -> tuple[Path, Path, Path]:
    repo = work / "repo"
    shutil.copytree(BASIC, repo)
    current = _rules(case)
    (repo / "modules" / "bastion" / "main.tf").write_text(_hcl(current), encoding="utf-8")
    state = json.loads((BASIC / "state.fixture.json").read_text(encoding="utf-8"))
    state["resources"][0]["instances"][0]["attributes"]["ingress"] = ingress_json(current)
    (repo / "state.fixture.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    finding = json.loads(FINDING.read_text(encoding="utf-8"))
    sg = finding["Findings"][0]["Resources"][0]["Details"]["AwsEc2SecurityGroup"]
    sg["IpPermissions"] = [
        {
            "IpProtocol": r.proto,
            "FromPort": r.from_port,
            "ToPort": r.to_port,
            "IpRanges": [{"CidrIp": r.cidr}],
        }
        for r in current
    ]
    finding_path = work / "finding.json"
    finding_path.write_text(json.dumps(finding, indent=2), encoding="utf-8")

    flows_path = work / "flows.json"
    flows_path.write_text(json.dumps(flows(case), indent=1), encoding="utf-8")
    return repo, finding_path, flows_path


def _observed(flows_path: Path) -> list[tuple[str, int, str]]:
    raw = json.loads(flows_path.read_text(encoding="utf-8"))
    proto = {"6": "tcp", "17": "udp"}
    return sorted(
        {(r["srcAddr"], int(r["dstPort"]), proto.get(r["protocol"], "tcp")) for r in raw["records"]}
    )


def score(
    case: Case, tool: str, rules: list[Rule], *, status: str = "FIXED", note: str = ""
) -> Outcome:
    def admitted(ip: str, port: int, proto: str) -> bool:
        net = ipaddress.ip_network(ip)
        return any(r.admits(net, port, proto) for r in rules)

    legit = [s for s in case.sources if s.legit]
    hostile = [(s.ip, s.port, s.proto, s.note) for s in case.sources if not s.legit]
    hostile += [
        (ip, p, "tcp", "new internet address")
        for ip in [PROBE, *case.extra_probes]
        for p in case.ports
    ]

    out = Outcome(tool, status, rules=[r.label() for r in rules], note=note)
    if status != "FIXED":
        return out
    out.broken = [
        f"{s.ip}:{s.port} ({s.note})" for s in legit if not admitted(s.ip, s.port, s.proto)
    ]
    out.exposed = [f"{ip}:{p} ({n})" for ip, p, pr, n in hostile if admitted(ip, p, pr)]
    for r in rules:
        if any(r.from_port <= p <= r.to_port or r.proto == "-1" for p in case.ports):
            out.total_addresses += r.net.num_addresses
            if not is_internal(r.net):
                out.internet_addresses += r.net.num_addresses
    if len(rules) > QUOTA:
        out.status, out.note = (
            "INVALID",
            f"{len(rules)} rules exceed the {QUOTA}-rule quota; AWS rejects it",
        )
    return out


# --- contenders ---------------------------------------------------------------------------


def posturanet(case: Case, work: Path) -> Outcome:
    repo, finding, flows_path = _repo(case, work)
    config, _ = load_config(repo)
    if case.approved:
        _approve(case, repo, config.contracts.dir)
    ctx = Context(
        mode="check",
        evidence=FileSource(flows_path),
        terraform=FakeTerraform(live_before=_rules(case)),
        clock=lambda: END,
    )
    record, proposal = run_fix_full(str(finding), repo, config, ctx)
    if proposal is None or record.result != "VALIDATED":
        stopped = next((s for s in record.stages if s.status.value in ("fail", "unknown")), None)
        why = stopped.summary if stopped else (record.why or record.result)
        return score(case, "PosturaNet", [], status="STOPPED", note=why)
    after = sorted({*proposal.synthesis.kept, *proposal.synthesis.added})
    out = score(case, "PosturaNet", after, note=record.result_detail or "")
    out.flagged = [f"{s.cidr}:{s.port}" for s in proposal.contract.needs_review]
    return out


def _approve(case: Case, repo: Path, contracts_dir: str) -> None:
    """Write the contract a team approved earlier, listing sources by hand."""
    by_ip = {s.ip: s for s in case.sources}
    contract = BehaviorContract(
        resource=ADDRESS,
        account="123456789012",
        region="us-east-1",
        observed=ObservedMeta(
            source="flow_logs_file",
            window=ObservedWindow(start=END.date(), end=END.date(), days=WINDOW_DAYS),
            confidence=Confidence.HIGH,
        ),
        must_allow=[
            NetRule(cidr=f"{ip}/32", port=by_ip[ip].port, proto="tcp", owner=by_ip[ip].note)
            for ip in case.approved
        ],
        must_deny=default_must_deny(_rules(case), set(case.ports)),
        status="approved",
        approved_by="platform-team",
    )
    write_contract(contract_path(repo, contracts_dir, ADDRESS), contract)


def revoke(case: Case, work: Path) -> Outcome:
    """Delete every rule open to the internet (the shape of a typical automated remediation)."""
    return score(case, "Revoke open rule", [r for r in _rules(case) if not r.is_world])


def private_only(case: Case, work: Path) -> Outcome:
    """Swap the internet for the RFC 1918 ranges (a common hand fix)."""
    out: list[Rule] = []
    for r in _rules(case):
        out += [Rule(p, r.from_port, r.to_port, r.proto) for p in PRIVATE] if r.is_world else [r]
    return score(case, "Private ranges only", sorted(set(out)))


def allow_observed(case: Case, work: Path) -> Outcome:
    """Allow every source seen in the flow logs as a /32 (evidence without judgment)."""
    _, _, flows_path = _repo(case, work)
    kept = [r for r in _rules(case) if not r.is_world]
    added = [Rule(f"{ip}/32", port, port, proto) for ip, port, proto in _observed(flows_path)]
    return score(case, "Allow all observed", sorted({*kept, *added}))


CONTENDERS: list[Callable[[Case, Path], Outcome]] = [
    posturanet,
    revoke,
    private_only,
    allow_observed,
]


# --- report -------------------------------------------------------------------------------


def run() -> dict[str, list[Outcome]]:
    results: dict[str, list[Outcome]] = {}
    for case in CASES:
        results[case.id] = []
        for contender in CONTENDERS:
            with tempfile.TemporaryDirectory() as tmp:
                results[case.id].append(contender(case, Path(tmp)))
    return results


def _fmt_addresses(n: int) -> str:
    if n >= 1_000_000_000:
        return f"{n / 1e9:.1f}B"
    if n >= 1_000_000:
        return f"{n / 1e6:.1f}M"
    return str(n)


def report(results: dict[str, list[Outcome]]) -> str:
    tools = [o.tool for o in next(iter(results.values()))]
    verdicts = ["CORRECT", "STOPPED", "OUTAGE", "STILL EXPOSED", "INVALID"]
    lines = [
        "# PosturaNet benchmark results",
        "",
        f"Generated by `python -m bench` · {len(results)} cases · "
        "security group ingress (EC2.19-style findings).",
        "",
        "| Contender | "
        + " | ".join(v.title() for v in verdicts)
        + " | Addresses opened, all fixes |",
        "|---|" + "---|" * (len(verdicts) + 1),
    ]
    for i, tool in enumerate(tools):
        counts = [sum(1 for outs in results.values() if outs[i].verdict == v) for v in verdicts]
        opened = sum(
            outs[i].total_addresses for outs in results.values() if outs[i].status == "FIXED"
        )
        lines.append(
            f"| {tool} | " + " | ".join(str(c) for c in counts) + f" | {_fmt_addresses(opened)} |"
        )
    lines += [
        "",
        "**Correct**: every legit source still works and every hostile source is blocked. "
        "**Stopped**: the tool declined to change anything and said why. "
        "**Outage**: the fix blocks a source that must keep working. "
        "**Still exposed**: the fix leaves a hostile source allowed. "
        "**Invalid**: the fix cannot be applied (over the 60-rule quota). "
        "**Addresses opened** sums every address (internal and internet) the fixes still allow on "
        "the finding's ports; lower is closer to least privilege.",
        "",
        "### Per case",
        "",
    ]
    by_id = {c.id: c for c in CASES}
    for cid, outs in results.items():
        case = by_id[cid]
        lines += [
            f"#### `{cid}`: {case.title}",
            "",
            case.why,
            "",
            "| Contender | Verdict | Addresses allowed (internet) | Detail |",
            "|---|---|---|---|",
        ]
        for o in outs:
            detail = "; ".join(
                x
                for x in [
                    ("blocks " + ", ".join(o.broken)) if o.broken else "",
                    ("allows " + ", ".join(o.exposed)) if o.exposed else "",
                    ("asks a human about " + ", ".join(o.flagged)) if o.flagged else "",
                    o.note if o.status != "FIXED" else "",
                ]
                if x
            )
            addr = (
                f"{_fmt_addresses(o.total_addresses)} ({_fmt_addresses(o.internet_addresses)})"
                if o.status == "FIXED"
                else "-"
            )
            lines.append(f"| {o.tool} | {o.verdict.title()} | {addr} | {detail or '-'} |")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    from bench import iam, s3

    results = run()
    s3_results = s3.run()
    iam_results = iam.run()
    out_dir = Path(__file__).resolve().parent
    head, rest = report(results).split("\n", 1)
    sg_text = f"{head}\n\n## Security groups (EC2.19-style findings)\n{rest}"
    text = "\n".join([sg_text, "", *s3.report(s3_results), *iam.report(iam_results)])
    (out_dir / "RESULTS.md").write_text(text.rstrip() + "\n", encoding="utf-8")
    families = {"sg": results, "s3": s3_results, "iam": iam_results}
    payload = {
        name: {k: [asdict(o) | {"verdict": o.verdict} for o in v] for k, v in fam.items()}
        for name, fam in families.items()
    }
    (out_dir / "results.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for fam in families.values():
        for cid, outs in fam.items():
            print(f"{cid:30} " + "  ".join(f"{o.tool}={o.verdict}" for o in outs))
    return 0
