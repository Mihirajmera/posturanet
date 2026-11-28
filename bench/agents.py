"""Run AI coding agents on the security-group cases and score their fixes like every contender.

    python -m bench.agents --name claude-code --condition evidence --runs 3 \\
        --agent 'claude -p "$(cat TASK.md)" --permission-mode acceptEdits'

Each run gets a fresh copy of the case: the Terraform repo and `finding.json`, plus
`flows.json` (condition `evidence`), plus PosturaNet's contract check (condition `check`:
`posturanet` on PATH, an `.mcp.json` for `posturanet mcp`, and the contract PosturaNet would
build). The task is in `TASK.md`. The agent edits `modules/bastion/main.tf`, or writes
`STOP.md` to decline. The harness reads the security group back and scores it with the same
ground truth as `python -m bench` (`run.score`).

Safety: agents run in a temporary directory of synthetic files, with every AWS_* variable
removed from their environment, so no cloud account is reachable from the run. The command
comes from the person running the benchmark, never from a case file.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from bench.cases import CASES, Case
from bench.run import ADDRESS, Outcome, _repo, score
from posturanet.errors import StageStop
from posturanet.synth.sg_rules import parse_security_group

CONDITIONS = ("finding", "evidence", "check")
MAIN_TF = Path("modules") / "bastion" / "main.tf"
_SG = re.compile(r'^resource\s+"aws_security_group"\s+"this"', re.MULTILINE)

_TASK = """\
# Task

`finding.json` is an AWS Security Hub finding: the security group in
`modules/bastion/main.tf` ({address}) allows {ports} from the internet (0.0.0.0/0).

Fix it in the Terraform code so the finding is resolved **without breaking anyone who really
uses this security group**. {evidence}{check}

Edit `modules/bastion/main.tf` only. If you can't fix it without risking an outage, don't
change the file: write your reason in `STOP.md` instead. Don't run terraform apply; there is
no AWS account.
"""

_EVIDENCE = (
    "`flows.json` holds 90 days of VPC flow logs for the group's network interfaces "
    "(fields: srcAddr, dstPort, protocol, bytes, start)."
)
_CHECK = (
    "\n\nPosturaNet is installed. Before you finish, run "
    "`posturanet contract check --source --repo .` (or the MCP tool `check_change`) and don't "
    "finish on BLOCK."
)


def _prepare(case: Case, condition: str, work: Path) -> Path:
    repo, finding, flows = _repo(case, work)
    (repo / "finding.json").write_bytes(finding.read_bytes())
    if condition in ("evidence", "check"):
        (repo / "flows.json").write_bytes(flows.read_bytes())
    if condition == "check":
        _contract(case, repo, flows)
        mcp = {"mcpServers": {"posturanet": {"command": "posturanet", "args": ["mcp"]}}}
        (repo / ".mcp.json").write_text(json.dumps(mcp, indent=2), encoding="utf-8")
    ports = ", ".join(str(p) for p in case.ports)
    task = _TASK.format(
        address=ADDRESS,
        ports=f"port {ports}" if len(case.ports) == 1 else f"ports {ports}",
        evidence=_EVIDENCE if condition != "finding" else "",
        check=_CHECK if condition == "check" else "",
    )
    (repo / "TASK.md").write_text(task, encoding="utf-8")
    return repo


def _contract(case: Case, repo: Path, flows: Path) -> None:
    """The draft contract PosturaNet builds from the same evidence (`contract build`)."""
    from bench.run import END, FakeTerraform, _rules
    from posturanet.evidence import FileSource
    from posturanet.models.config import load_config
    from posturanet.pipeline import Context, run_fix

    config, _ = load_config(repo)
    finding = repo / "finding.json"
    ctx = Context(
        mode="check",
        evidence=FileSource(flows),
        terraform=FakeTerraform(live_before=_rules(case)),
        clock=lambda: END,
        stop_after="contract",
    )
    run_fix(str(finding), repo, config, ctx)


def _env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("AWS_")}


def read_fix(case: Case, repo: Path, before: str, tool: str, note: str = "") -> Outcome:
    """Score what the agent left in the repo."""
    main = repo / MAIN_TF
    text = main.read_text(encoding="utf-8") if main.is_file() else ""
    stop = repo / "STOP.md"
    if text == before:
        why = stop.read_text(encoding="utf-8").strip()[:300] if stop.is_file() else "no change"
        return score(case, tool, [], status="STOPPED", note=why)
    m = _SG.search(text)
    if m is None:
        return Outcome(tool, "INVALID", note="the security group resource is gone")
    line = text.count("\n", 0, m.start()) + 1
    try:
        rules = parse_security_group(main, line, "aws_security_group", "this").rules()
    except StageStop as exc:
        return Outcome(tool, "INVALID", note=f"can't read the fix: {exc.reason}")
    return score(case, tool, rules, note=note)


def run_one(case: Case, condition: str, agent: str, tool: str, timeout: int) -> Outcome:
    with tempfile.TemporaryDirectory(prefix=f"pn-agent-{case.id}-") as tmp:
        repo = _prepare(case, condition, Path(tmp))
        before = (repo / MAIN_TF).read_text(encoding="utf-8")
        try:
            # shell=True: the command is the operator's own, e.g. `claude -p "$(cat TASK.md)"`
            subprocess.run(agent, shell=True, cwd=repo, env=_env(), timeout=timeout, check=False)  # noqa: S602
        except subprocess.TimeoutExpired:
            return score(case, tool, [], status="STOPPED", note=f"timed out after {timeout}s")
        return read_fix(case, repo, before, tool)


def table(rows: dict[str, list[Outcome]]) -> list[str]:
    verdicts = ["CORRECT", "STOPPED", "OUTAGE", "STILL EXPOSED", "INVALID"]
    lines = [
        "| Agent · condition | Runs | " + " | ".join(v.title() for v in verdicts) + " |",
        "|---|---|" + "---|" * len(verdicts),
    ]
    for key, outs in rows.items():
        c = Counter(o.verdict for o in outs)
        lines.append(f"| {key} | {len(outs)} | " + " | ".join(str(c[v]) for v in verdicts) + " |")
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m bench.agents", description=__doc__.split("\n")[0])
    ap.add_argument("--agent", required=True, help="shell command, run in the case directory")
    ap.add_argument("--name", required=True, help="label for the results, e.g. claude-code")
    ap.add_argument("--condition", choices=CONDITIONS, default="finding")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--case", action="append", help="only these case ids (repeatable)")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    cases = [c for c in CASES if not args.case or c.id in args.case]
    key = f"{args.name} · {args.condition}"
    runs: list[tuple[str, Outcome]] = []
    for case in cases:
        for n in range(args.runs):
            o = run_one(case, args.condition, args.agent, args.name, args.timeout)
            runs.append((case.id, o))
            print(f"{case.id} run {n + 1}: {o.verdict}", file=sys.stderr)
    out = args.out or Path(__file__).parent / f"agents-{args.name}-{args.condition}.json"
    data = {
        "agent": args.name,
        "condition": args.condition,
        "runs": args.runs,
        "results": [{"case": cid, "verdict": o.verdict, **asdict(o)} for cid, o in runs],
    }
    out.write_text(json.dumps(data, indent=1), encoding="utf-8")
    print("\n".join(table({key: [o for _, o in runs]})))
    return 0


if __name__ == "__main__":
    sys.exit(main())
