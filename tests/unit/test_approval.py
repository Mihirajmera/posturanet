"""Approving an IAM stop at the terminal: preview, then the decision goes into the contract."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fakes import IamTerraform
from posturanet.cli import app as cli
from posturanet.evidence import FileSource
from posturanet.iamfix import contract as iamcontract
from posturanet.iamfix.pr import _approval_rows
from posturanet.models.config import load_config
from posturanet.models.iam import IamApproval
from posturanet.pipeline import Context, run_fix

FIXTURES = Path(__file__).parent.parent / "fixtures"
DEPLOY = str(FIXTURES / "findings" / "iam21_deploy.json")
ADMIN = str(FIXTURES / "findings" / "iam1_admin.json")
CONTRACT = "posturanet/contracts/aws_iam_policy.deploy.yaml"
APPROVAL = IamApproval(reviewed_services=["s3"], keep=["s3:GetObject"], by="dana", at="2026-10-30")


def _clock() -> datetime:
    return datetime(2026, 10, 30, 6, tzinfo=UTC)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    out = tmp_path / "repo"
    shutil.copytree(FIXTURES / "tf" / "iam", out)
    return out


def _ctx(name: str, **kw: object) -> Context:
    ev = FileSource(FIXTURES / "iam" / f"{name}.json")
    return Context(evidence=ev, terraform=IamTerraform(name), clock=_clock, **kw)  # type: ignore[arg-type]


def test_stop_lists_what_a_person_can_approve(repo: Path) -> None:
    config, _ = load_config(repo)
    stopped = run_fix(DEPLOY, repo, config, _ctx("deploy", mode="check"))
    assert stopped.result == "STOPPED"
    assert [(a.kind, a.name) for a in stopped.approvals] == [("data_plane", "s3")]
    assert stopped.approvals[0].used, "the actions seen in use are shown before approving"
    assert any("at a terminal" in s for s in stopped.next_steps)

    admin = run_fix(ADMIN, repo, config, _ctx("admin", mode="dry-run"))
    assert ("untracked", "iam:PassRole") in {(a.kind, a.name) for a in admin.approvals}


def test_preview_writes_nothing_then_approval_goes_into_the_contract(repo: Path) -> None:
    config, _ = load_config(repo)
    run_fix(DEPLOY, repo, config, _ctx("deploy", mode="check"))  # writes the draft
    draft = (repo / CONTRACT).read_text(encoding="utf-8")

    preview = run_fix(
        DEPLOY, repo, config, _ctx("deploy", mode="check", approval=APPROVAL, preview=True)
    )
    assert preview.result == "VALIDATED", preview.stages
    assert preview.diff is not None and "s3:GetObject" in preview.diff.files[0].new_content
    assert (repo / CONTRACT).read_text(encoding="utf-8") == draft, "preview writes nothing"

    final = run_fix(DEPLOY, repo, config, _ctx("deploy", mode="check", approval=APPROVAL))
    assert final.result == "VALIDATED"
    contract = iamcontract.load(repo / CONTRACT)
    assert contract is not None and contract.status == "approved"
    assert contract.approved_by == "dana" and contract.approved_at == "2026-10-30"
    assert "s3" in contract.reviewed_services
    kept = [a for a in contract.must_allow if a.action == "s3:GetObject"]
    assert kept and kept[0].source == "human" and kept[0].owner == "dana"


def test_pr_says_who_approved() -> None:
    assert _approval_rows(None) == []
    row = _approval_rows(APPROVAL)[0]
    assert "dana" in row and "reviewed s3" in row and "kept `s3:GetObject`" in row


def test_cli_asks_then_shows_the_change(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    args = ["fix", DEPLOY, "--dry-run", "--repo", str(repo), "--evidence-file"]
    args.append(str(FIXTURES / "iam" / "deploy.json"))
    runner = CliRunner()

    typo = runner.invoke(cli.app, args, input="ec2:Foo\ns3:GetObject\ny\ny\n")
    assert "not s3 actions: ec2:Foo" in typo.output
    assert "Approve this change?" in typo.output and typo.exit_code == 0, typo.output
    assert "s3:GetObject" in typo.output

    declined = runner.invoke(cli.app, args, input="\nn\n")
    assert declined.exit_code == 3 and "Not approved" in declined.output

    monkeypatch.setattr(cli, "_interactive", lambda: False)
    plain = runner.invoke(cli.app, args)
    assert plain.exit_code == 3 and "Approve" not in plain.output  # CI and pipes never prompt
