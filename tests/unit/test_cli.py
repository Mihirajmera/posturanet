from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from posturanet import __version__
from posturanet.cli.app import app

runner = CliRunner()

EXPECTED_DRY_RUN = f"""PosturaNet {__version__} - fix - {{target}}

  [ok] ingest      securityhub EC2.19 - sg-0a91f3c2 - HIGH
  [ok] locate      modules/bastion/main.tf:5 -> module.bastion.aws_security_group.this - @example-org/platform-network
  [-]  evidence    dry run: pass --evidence-file to go further
  [-]  contract    dry run: pass --evidence-file to go further
  [-]  fix         dry run: pass --evidence-file to go further
  [-]  validate    dry run: pass --evidence-file to go further
  [-]  deliver     dry run: pass --evidence-file to go further

Result   DRY RUN - ingest and locate complete - no AWS calls, no changes

Unknowns
  - drift: not checked (needs terraform plan)

Next
  - re-run with --evidence-file <flows.json> to see the proposed fix offline
  - or drop --dry-run to read flow logs with the read-only role
"""


def test_dry_run_ascii(sg_finding_path: Path, basic_repo: Path) -> None:
    target = str(sg_finding_path)
    result = runner.invoke(app, ["fix", target, "--dry-run", "--repo", str(basic_repo), "--ascii"])
    assert result.exit_code == 0, result.output
    assert result.output == EXPECTED_DRY_RUN.format(target=target)


def test_dry_run_json(sg_finding_path: Path, basic_repo: Path) -> None:
    result = runner.invoke(
        app,
        ["fix", str(sg_finding_path), "--dry-run", "--repo", str(basic_repo), "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    assert doc["result"] == "DRY RUN"
    assert doc["location"]["drift"] is None
    assert doc["finding"]["provenance"]["schema"] == "asff-2018-10-08"
    assert [s["name"] for s in doc["stages"]][:2] == ["ingest", "locate"]


def test_stop_exits_3(basic_repo: Path) -> None:
    result = runner.invoke(
        app, ["fix", "sg-ffffffff", "--dry-run", "--repo", str(basic_repo), "--ascii"]
    )
    assert result.exit_code == 3
    assert "[x]  locate      sg-ffffffff is not in the Terraform state" in result.output
    assert "Result   STOPPED - locate stopped - no PR opened" in result.output
    assert re.search(r"\[-\]\s+evidence\s+not run", result.output)


def test_dry_run_and_open_pr_conflict(sg_finding_path: Path, basic_repo: Path) -> None:
    args = ["fix", str(sg_finding_path), "--dry-run", "--open-pr", "--repo", str(basic_repo)]
    assert runner.invoke(app, args).exit_code == 2


def test_dry_run_with_evidence(sg_finding_path: Path, basic_repo: Path, flows_path: Path) -> None:
    args = ["fix", str(sg_finding_path), "--dry-run", "--repo", str(basic_repo), "--ascii"]
    result = runner.invoke(app, [*args, "--evidence-file", str(flows_path)])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "[ok] evidence    flow logs (file) - 89 days - confidence high - 5 sources" in out
    assert "203.0.113.7/32       1,067 conns - 22/tcp - daily at 02:00 UTC  [!] external" not in out
    assert (
        "198.51.100.23/32         3 conns - 22/tcp - one_off  ! not kept, likely a scanner" in out
    )
    assert "[!]  contract    built (not written)" in out
    assert "Proposed change" in out
    assert '+    cidr_blocks = ["10.0.4.12/32", "10.0.4.37/32", "10.0.5.9/32"' in out
    assert "Result   DRY RUN - risk medium - disruption none - no AWS calls, no changes" in out


def test_window_validation(sg_finding_path: Path, basic_repo: Path) -> None:
    args = ["fix", str(sg_finding_path), "--dry-run", "--repo", str(basic_repo), "--window", "9y"]
    assert runner.invoke(app, args).exit_code == 2


def test_init_prints_policy() -> None:
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert json.loads(result.output)["Statement"][0]["Sid"] == "PosturaNetReadOnly"


def test_usage_error_exit_2(basic_repo: Path) -> None:
    result = runner.invoke(app, ["fix", "vpc-1", "--dry-run", "--repo", str(basic_repo)])
    assert result.exit_code == 2


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
