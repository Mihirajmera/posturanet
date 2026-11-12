"""Live event demo: 3 real PosturaNet runs on the synthetic fixtures, about 2 minutes.

Offline: no AWS, no network, nothing written outside a temp folder. From a clone of the repo:

    pip install posturanet        # or pip install -e .
    python docs/media/live.py     # press Enter to run each step and to move on
    python docs/media/live.py --auto   # rehearsal: no pauses

Each step shows what to say, then runs the real command in this terminal.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make  # noqa: E402  (same fixtures and contract as the README recordings)

AUTO = "--auto" in sys.argv
sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)  # type: ignore[union-attr]  # keep our lines in order with the child's
DIM, BOLD, BLUE, OFF = "\x1b[2m", "\x1b[1m", "\x1b[34m", "\x1b[0m"


def pause(prompt: str) -> None:
    if not AUTO:
        input(f"{DIM}{prompt}{OFF}")


def step(n: int, say: str, args: list[str], cwd: Path) -> None:
    os.system("cls" if os.name == "nt" else "clear") if not AUTO else print()
    print(f"{BLUE}{BOLD}{n}/3{OFF}  {say}\n")
    print(f"{BOLD}$ posturanet {' '.join(args)}{OFF}")
    pause("  [Enter] run")
    env = {**os.environ, "FORCE_COLOR": "1", "POSTURANET_NO_BANNER": "1", "PYTHONUTF8": "1"}
    subprocess.run([sys.executable, "-m", "posturanet", *args], cwd=cwd, env=env, check=False)
    pause("\n  [Enter] next")


def main() -> None:
    started = time.monotonic()
    step(
        1,
        "A Prowler scan. Your scanner finds issues; PosturaNet says what each one ends in: "
        "a fix PR, a runbook, an accepted exception, or nothing yet.",
        ["findings", "list", "findings/prowler_ocsf_scan.json", "--all"],
        make.FIX,
    )
    step(
        2,
        "SSH open to the internet. Removing it blindly breaks whoever really connects. "
        "PosturaNet reads 89 days of flow logs, keeps the 4 real sources, drops a scanner, "
        "flags the outside partner, and computes the smallest rule set.",
        [
            "fix",
            "findings/sg_ssh_open.json",
            "--dry-run",
            "--repo",
            "tf/basic",
            "--evidence-file",
            "flows/bastion_90d.json",
        ],
        make.FIX,
    )
    repo = make._gate_repo()
    try:
        step(
            3,
            "Weeks later an AI coding agent rewrites the IAM policy and puts ec2:* back. "
            "The contract check blocks it, in the agent or in CI, before anyone reviews it.",
            ["contract", "check", "--source", "--repo", "."],
            repo,
        )
    finally:
        shutil.rmtree(repo, ignore_errors=True)
    print(
        f"\n{BOLD}pip install posturanet{OFF}   ·   posturanet.com/#demo   ·   "
        "github.com/Mihirajmera/posturanet"
    )
    print(f"{DIM}Read-only role. Runs in your CI. A person merges every PR.{OFF}")
    if AUTO:
        print(f"{DIM}(commands ran in {time.monotonic() - started:.1f} s){OFF}")


if __name__ == "__main__":
    main()
