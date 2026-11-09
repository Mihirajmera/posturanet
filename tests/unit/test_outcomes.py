from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from posturanet.cli.app import app
from posturanet.errors import UsageError
from posturanet.ingest import read_findings
from posturanet.outcomes import EXCEPTIONS_FILE, load_exceptions, outcome, runbook_for

SCAN = Path("tests/fixtures/findings/prowler_ocsf_scan.json")  # 0 EC2.13 fix, 1 PASS, 2 ACM.1, ...
EXC = """exceptions:
  - control: S3.8
    resource: acme-assets
    owner: web-team
    reason: website bucket behind CloudFront
    expires: 2027-03-31
  - control: RDS.8
    owner: data-team
    reason: old
    expires: 2025-01-01
"""
TODAY = date(2026, 11, 9)


def test_each_finding_gets_an_outcome(tmp_path: Path) -> None:
    (tmp_path / "exc.yaml").write_text(EXC, encoding="utf-8")
    accepted = load_exceptions(tmp_path / "exc.yaml")
    got = {e.index: outcome(e, accepted, TODAY) for e in read_findings(SCAN).entries}
    assert got[0] == ("fix", None)
    assert got[1] == ("passed", None)
    assert got[2] == ("none", None)
    assert got[3] == ("exception", "accepted by web-team until 2027-03-31")
    assert got[4] == ("fix", "exception expired 2025-01-01")  # expired: the finding comes back


def test_exceptions_file_is_checked(tmp_path: Path) -> None:
    assert load_exceptions(EXCEPTIONS_FILE) == [] or EXCEPTIONS_FILE.is_file()  # default: optional
    with pytest.raises(UsageError, match="not found"):
        load_exceptions(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("exceptions:\n  - control: S3.8\n    owner: x\n", encoding="utf-8")
    with pytest.raises(UsageError, match="not a valid exceptions file"):
        load_exceptions(bad)  # no reason, no expiry


def test_runbooks() -> None:
    steps = runbook_for("IAM.6")
    assert steps and all(isinstance(s, str) and s for s in steps)
    assert runbook_for("EC2.13") is None and runbook_for(None) is None


def test_cli(tmp_path: Path) -> None:
    (tmp_path / "exc.yaml").write_text(EXC, encoding="utf-8")
    runner = CliRunner()
    args = ["findings", "list", str(SCAN), "--all", "--exceptions", str(tmp_path / "exc.yaml")]
    text = runner.invoke(app, args).output
    assert "4 failed · 2 fix · 0 runbook · 1 accepted · coverage 3/4 (75%)" in text
    rows = json.loads(runner.invoke(app, [*args, "--format", "json"]).output)
    assert [r["outcome"] for r in rows] == ["fix", "passed", "none", "exception", "fix"]

    out = tmp_path / "split"
    split = ["findings", "split", str(SCAN), "--out", str(out)]
    assert runner.invoke(app, [*split, "--exceptions", str(tmp_path / "exc.yaml")]).exit_code == 0
    assert not any("acme-assets" in p.name for p in out.iterdir())  # accepted risk skipped

    shown = runner.invoke(app, ["fixes", "show", "IAM.9"])
    assert shown.exit_code == 0 and "runbook" in shown.output
