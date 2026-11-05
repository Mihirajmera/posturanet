from __future__ import annotations

from pathlib import Path

import pytest

from fakes import FakeGitHub, FakeTerraform
from posturanet.deliver import GitHub, deliver
from posturanet.deliver.idempotency import contract_sha, finding_tag, key_in, markers
from posturanet.deliver.pr_body import body, labels, title
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix_full
from posturanet.proposal import Proposal

TF = "modules/bastion/main.tf"


def _proposal(repo: Path, flows: Path, finding: Path) -> Proposal:
    config, _ = load_config(repo)
    ctx = Context(mode="check", evidence=FileSource(flows), terraform=FakeTerraform())
    _, p = run_fix_full(str(finding), repo, config, ctx)
    assert p is not None
    return p


def test_contract_sha_ignores_counts(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    p = _proposal(tmp_repo, flows_path, sg_finding_path)
    bumped = p.contract.model_copy(
        update={"must_allow": [r.model_copy(update={"count": 1}) for r in p.contract.must_allow]}
    )
    assert contract_sha(bumped) == contract_sha(p.contract)


def test_title_and_labels(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    p = _proposal(tmp_repo, flows_path, sg_finding_path)
    assert len(title(p)) <= 72
    assert labels(p, ["posturanet", "security"]) == [
        "posturanet",
        "security",
        "risk:medium",
        "needs-review",
    ]


def test_body_sections(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    p = _proposal(tmp_repo, flows_path, sg_finding_path)
    text = body(p, run_id="run_x")
    assert text.startswith(markers(p.idempotency_key, p.finding.finding_id))
    assert key_in(text) == p.idempotency_key
    for heading in (
        "### What changes",
        "### What's using this resource (observed)",
        "### Checks",
        "### Unknowns and residual risk",
        "### Before you merge",
        "### After merge",
        "<summary>Safety contract (machine-readable)</summary>",
    ):
        assert heading in text
    assert "| 203.0.113.7/32 | 22/tcp | 1,067 | daily at 02:00 UTC · needs review | ✓ |" in text
    assert (
        "| 198.51.100.23/32 | 22/tcp | 3 | one_off · not kept: internet source seen on 1 day(s)"
        in text
    )
    assert "89 days, except 1 likely scanner (listed below)." in text
    assert "needs review" in text
    assert "model_scope:" in text
    for banned in ("proven safe", "guaranteed", "100% safe", "zero risk"):
        assert banned not in text.lower()
    # Untrusted finding text never reaches the PR body (NFR-4).
    assert "prompt-injection canary" not in text


def _gh(fake: FakeGitHub) -> GitHub:
    return GitHub("token", "acme/infra", fake.client())


def _deliver(
    gh: GitHub, p: Proposal, originals: dict[str, str | None], max_open: int = 5
) -> object:
    return deliver(gh, p, base="main", labels=["posturanet"], max_open=max_open, local_originals=originals, run_id="r")  # fmt: skip


def test_base_mismatch_stops(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    p = _proposal(tmp_repo, flows_path, sg_finding_path)
    fake = FakeGitHub({TF: "something else"})
    with pytest.raises(StageStop, match="differs from the local checkout"):
        _deliver(_gh(fake), p, {TF: (tmp_repo / TF).read_text(encoding="utf-8")})
    assert fake.writes == []


def test_rate_limit(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    p = _proposal(tmp_repo, flows_path, sg_finding_path)
    others = [{"number": i, "body": "", "labels": [{"name": "posturanet"}], "head": {"ref": f"posturanet/x/{i}"}, "html_url": ""} for i in range(2)]  # fmt: skip
    with pytest.raises(StageStop, match="already open"):
        _deliver(_gh(FakeGitHub({}, others)), p, {}, max_open=2)


def test_existing_pr_for_finding_is_updated(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    p = _proposal(tmp_repo, flows_path, sg_finding_path)
    old = {
        "number": 7,
        "html_url": "https://github.com/acme/infra/pull/7",
        "body": f"<!-- posturanet:key={'0' * 64} -->\n<!-- posturanet:finding={finding_tag(p.finding.finding_id)} -->",  # fmt: skip
        "labels": [{"name": "posturanet"}],
        "head": {"ref": "posturanet/sg_ingress/bastion-00000000"},
    }
    fake = FakeGitHub({TF: (tmp_repo / TF).read_text(encoding="utf-8")}, [old])
    fake.refs["posturanet/sg_ingress/bastion-00000000"] = "old"
    result = _deliver(_gh(fake), p, {TF: (tmp_repo / TF).read_text(encoding="utf-8")})
    assert result.action == "updated" and result.number == 7  # type: ignore[attr-defined]
    assert ("PATCH", "/repos/acme/infra/pulls/7") in fake.writes
    assert not any(m == "POST" and path.endswith("/pulls") for m, path in fake.writes)


def test_refuses_non_posturanet_branch() -> None:
    gh = GitHub("t", "acme/infra", FakeGitHub({}).client())
    with pytest.raises(StageStop, match="not a PosturaNet branch"):
        gh.set_branch("main", "sha", exists=True)
