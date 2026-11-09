"""Record PosturaNet demos as animated terminal SVGs (README and docs).

Every frame is real output: each demo runs the command against the synthetic fixtures in
`tests/fixtures/` and draws what it printed. Re-run after an output change:

    python docs/media/make.py

Writes `docs/media/*.svg`. No network, no AWS, nothing outside `docs/media/`.
"""

# ruff: noqa: E501  (SVG template lines)
from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
FIX = ROOT / "tests" / "fixtures"

# Design system 10.2 dark tokens.
BG, SURFACE, TEXT, MUTED = "#0B0E0F", "#1A1F1D", "#E8E6E1", "#919693"
ANSI = {"31": "#E5484D", "32": "#2FBF71", "33": "#EAB308", "34": "#4C6EF5"}
CHAR_W, LINE_H, PAD, BAR = 8.4, 19, 18, 34
FONT = "'JetBrains Mono','Cascadia Mono',Consolas,monospace"


def run(args: list[str], cwd: Path = ROOT, stdin: str | None = None) -> str:
    env = {**os.environ, "FORCE_COLOR": "1", "POSTURANET_NO_BANNER": "1", "PYTHONUTF8": "1"}
    env.pop("NO_COLOR", None)
    proc = subprocess.run(
        [sys.executable, "-m", "posturanet", *args],
        cwd=cwd,
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return proc.stdout


_SGR = re.compile(r"\x1b\[([0-9;]*)m")


def _spans(line: str) -> str:
    """ANSI SGR → <tspan>s with design-system colors."""
    out, fill, bold, dim, pos = [], None, False, False, 0
    for m in _SGR.finditer(line + "\x1b[0m"):
        chunk = line[pos : m.start()]
        if chunk:
            attrs = []
            color = MUTED if dim else (fill or TEXT)
            attrs.append(f'fill="{color}"')
            if bold:
                attrs.append('font-weight="700"')
            out.append(f"<tspan {' '.join(attrs)}>{html.escape(chunk)}</tspan>")
        codes = (m.group(1) or "0").split(";")
        if codes[:2] == ["38", "2"] and len(codes) == 5:  # truecolor (the banner)
            fill = "#{:02X}{:02X}{:02X}".format(*map(int, codes[2:]))
            codes = []
        for code in codes:
            if code == "0":
                fill, bold, dim = None, False, False
            elif code == "1":
                bold = True
            elif code == "2":
                dim = True
            elif code in ANSI:
                fill = ANSI[code]
        pos = m.end()
    return "".join(out)


def svg(title: str, command: str, output: str) -> str:
    lines = output.rstrip("\n").split("\n")
    lines = [line.replace("\t", "    ") for line in lines]
    width_cols = max(80, len(command) + 2, *(len(_SGR.sub("", line)) for line in lines)) + 1
    width = round(width_cols * CHAR_W + 2 * PAD)
    height = BAR + PAD + (len(lines) + 2) * LINE_H + PAD
    type_s = min(1.6, 0.03 * len(command))
    rows = [
        f'<text x="{PAD}" y="{BAR + PAD + 13}" class="t">'
        f'<tspan fill="{ANSI["32"]}">$ </tspan><tspan fill="{TEXT}">{html.escape(command)}</tspan>'
        "</text>",
        f'<rect x="{PAD + 2 * CHAR_W}" y="{BAR + PAD}" width="{len(command) * CHAR_W:.1f}" '
        f'height="{LINE_H}" fill="{BG}" class="type"/>',
    ]
    for i, line in enumerate(lines):
        y = BAR + PAD + 13 + (i + 2) * LINE_H
        delay = type_s + 0.35 + i * 0.07
        rows.append(
            f'<text x="{PAD}" y="{y}" class="t ln" style="animation-delay:{delay:.2f}s">'
            f"{_spans(line)}</text>"
        )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">
<title>{html.escape(title)}</title>
<style>
.t {{ font: 13.5px {FONT}; white-space: pre; }}
.ln {{ opacity: 0; animation: show .01s forwards; }}
.type {{ transform-box: fill-box; transform-origin: right; animation: type {type_s:.2f}s steps({max(len(command), 1)}) forwards; }}
@keyframes show {{ to {{ opacity: 1; }} }}
@keyframes type {{ to {{ transform: scaleX(0); }} }}
@media (prefers-reduced-motion: reduce) {{ .ln {{ opacity: 1; animation: none; }} .type {{ display: none; }} }}
</style>
<rect width="{width}" height="{height}" rx="10" fill="{BG}"/>
<rect width="{width}" height="{BAR}" rx="10" fill="{SURFACE}"/>
<rect y="{BAR - 10}" width="{width}" height="10" fill="{SURFACE}"/>
<circle cx="20" cy="17" r="6" fill="#E5484D"/><circle cx="40" cy="17" r="6" fill="#EAB308"/><circle cx="60" cy="17" r="6" fill="#2FBF71"/>
<text x="{width / 2}" y="22" text-anchor="middle" fill="{MUTED}" style="font: 12px {FONT}">{html.escape(title)}</text>
{chr(10).join(rows)}
</svg>
"""


# --- demos


def demo_sg() -> tuple[str, str, str]:
    args = [
        "fix", "findings/sg_ssh_open.json", "--dry-run",
        "--repo", "tf/basic", "--evidence-file", "flows/bastion_90d.json",
    ]  # fmt: skip
    title = "Security group: SSH open to the internet"
    return title, "posturanet " + " ".join(args), run(args, cwd=FIX)


def demo_iam() -> tuple[str, str, str]:
    args = [
        "fix", "findings/iam21_app.json", "--dry-run",
        "--repo", "tf/iam", "--evidence-file", "iam/app.json",
    ]  # fmt: skip
    title = "IAM: ec2:* shrunk to the actions in use"
    return title, "posturanet " + " ".join(args), run(args, cwd=FIX)


CONTRACT = {
    "resource": "aws_iam_policy.app",
    "kind": "iam",
    "policy_arn": "arn:aws:iam::123456789012:policy/app",
    "observed": {
        "source": "iam_last_accessed",
        "window": {"from": "2026-08-01", "to": "2026-10-30", "days": 90},
        "confidence": "high",
    },
    "must_allow": [
        {"action": "ec2:DescribeInstances", "owner": "@example-org/platform"},
        {"action": "logs:CreateLogStream", "owner": "@example-org/platform"},
    ],
    "must_remove": ["ec2:*"],
    "status": "approved",
}
EDITED = """resource "aws_iam_policy" "app" {
  name = "app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:*"]
        Resource = "*"
      },
    ]
  })
}
"""


def _gate_repo() -> Path:
    repo = Path(tempfile.mkdtemp(prefix="posturanet-demo-"))
    (repo / "main.tf").write_text(EDITED, encoding="utf-8")
    contracts = repo / "posturanet" / "contracts"
    contracts.mkdir(parents=True)
    (contracts / "aws_iam_policy.app.yaml").write_text(json.dumps(CONTRACT, indent=2), "utf-8")
    return repo


def demo_check() -> tuple[str, str, str]:
    repo = _gate_repo()
    try:
        out = run(["contract", "check", "--source", "--repo", "."], cwd=repo)
    finally:
        shutil.rmtree(repo, ignore_errors=True)
    title = "An agent puts ec2:* back: the contract check blocks it"
    return title, "posturanet contract check --source", out


def demo_hook() -> tuple[str, str, str]:
    repo = _gate_repo()
    try:
        event = json.dumps(
            {"tool_name": "Edit", "tool_input": {"file_path": str(repo / "main.tf")}}
        )
        raw = run(["hook", "claude-code", "--repo", "."], cwd=repo, stdin=event)
    finally:
        shutil.rmtree(repo, ignore_errors=True)
    reply = json.loads(raw)
    wrapped = [textwrap.fill(p, 96) for p in reply["reason"].split("\n")]
    body = f"decision: {reply['decision']}\n\n" + "\n".join(wrapped)
    body = body.replace("PosturaNet", "\x1b[1mPosturaNet\x1b[0m", 1)
    body = body.replace("BLOCK", "\x1b[31mBLOCK\x1b[0m", 1).replace(
        "decision: block", "decision: \x1b[31mblock\x1b[0m"
    )  # noqa: E501
    title = "Claude Code hook: what the agent is told after its edit"
    return title, "(Claude Code runs after Edit) posturanet hook claude-code", body


def _in_process(args: list[str], answers: str = "") -> str:
    """Run the CLI in this process, as if at a terminal, so prompts and answers show."""
    os.environ.update({"FORCE_COLOR": "1", "POSTURANET_NO_BANNER": "1"})
    os.environ.pop("NO_COLOR", None)
    from typer.testing import CliRunner

    from posturanet.cli import app as cli

    cli._interactive = lambda: True  # type: ignore[assignment]
    cwd = os.getcwd()
    os.chdir(FIX)
    try:
        return CliRunner().invoke(cli.app, args, input=answers).output
    finally:
        os.chdir(cwd)


def demo_start() -> tuple[str, str, str]:
    from posturanet.output import banner

    return "posturanet: every command, with an example", "posturanet", banner.render(color="truecolor")


def demo_connect() -> tuple[str, str, str]:
    title = "Connect a scanner, a coding agent or CI"
    return title, "posturanet connect", run(["connect"], cwd=FIX)


def demo_findings() -> tuple[str, str, str]:
    args = ["findings", "list", "findings/prowler_ocsf_scan.json", "--all"]
    title = "A Prowler scan: what each finding ends in, and coverage"
    return title, "posturanet " + " ".join(args), run(args, cwd=FIX)


def demo_approve() -> tuple[str, str, str]:
    args = [
        "fix", "findings/iam21_deploy.json", "--dry-run",
        "--repo", "tf/iam", "--evidence-file", "iam/deploy.json",
    ]  # fmt: skip
    out = _in_process(args, answers="s3:GetObject\ny\ny\n")
    title = "A person approves what IAM can't see, after the before and after"
    return title, "posturanet " + " ".join(args), out


DEMOS: dict[str, Callable[[], tuple[str, str, str]]] = {
    "start": demo_start,
    "connect": demo_connect,
    "findings-outcomes": demo_findings,
    "approve-iam": demo_approve,
    "fix-security-group": demo_sg,
    "fix-iam": demo_iam,
    "check-block": demo_check,
    "agent-hook": demo_hook,
}


def main() -> None:
    for name, make in DEMOS.items():
        title, command, output = make()
        if not output.strip():
            raise SystemExit(f"{name}: the command printed nothing")
        (OUT / f"{name}.svg").write_text(
            svg(title, command, output), encoding="utf-8", newline="\n"
        )
        print(f"wrote docs/media/{name}.svg")


if __name__ == "__main__":
    main()
