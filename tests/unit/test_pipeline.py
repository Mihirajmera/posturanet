from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from fakes import FakeGitHub, FakeTerraform
from posturanet.contracts import load_contract, write_contract
from posturanet.deliver import GitHub
from posturanet.evidence import FileSource
from posturanet.models import StageStatus
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix, run_fix_full

CONTRACT = "posturanet/contracts/module.bastion.aws_security_group.this.yaml"


def _ctx(flows: Path, **kw: Any) -> Context:
    return Context(evidence=FileSource(flows), terraform=FakeTerraform(), **kw)


def _status(record: Any) -> dict[str, StageStatus]:
    return {s.name: s.status for s in record.stages}


def test_check_mode_validates_and_writes_contract(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    config, _ = load_config(tmp_repo)
    record = run_fix(str(sg_finding_path), tmp_repo, config, _ctx(flows_path, mode="check"))
    assert record.result == "VALIDATED", record.stages
    assert record.exit_code == 0
    assert _status(record)["validate"] is StageStatus.OK
    assert _status(record)["deliver"] is StageStatus.SKIPPED
    assert record.location is not None and record.location.drift is False
    assert (tmp_repo / CONTRACT).is_file()
    assert record.next_steps[-1] == "re-run with --open-pr to open the pull request"


def test_dry_run_writes_nothing(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    config, _ = load_config(tmp_repo)
    before = sorted(p.as_posix() for p in tmp_repo.rglob("*"))
    record = run_fix(str(sg_finding_path), tmp_repo, config, _ctx(flows_path, mode="dry-run"))
    assert record.result == "DRY RUN"
    assert _status(record)["validate"] is StageStatus.WARN
    assert sorted(p.as_posix() for p in tmp_repo.rglob("*")) == before


def test_open_pr(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    config, _ = load_config(tmp_repo)
    tf_path = "modules/bastion/main.tf"
    fake = FakeGitHub({tf_path: (tmp_repo / tf_path).read_text(encoding="utf-8")})
    ctx = _ctx(flows_path, mode="open-pr", github=GitHub("t", "acme/infra", fake.client()))
    record, proposal = run_fix_full(str(sg_finding_path), tmp_repo, config, ctx)
    assert record.result == "OPENED", record.stages
    assert record.pr_url == "https://github.com/acme/infra/pull/412"
    assert proposal is not None
    branch = fake.prs[0]["head"]["ref"]
    assert branch.startswith("posturanet/sg_ingress/bastion-")
    assert '"10.0.4.12/32"' in fake.files[(branch, tf_path)]
    assert (branch, CONTRACT) in fake.files
    assert ("main", tf_path) in fake.files and '"0.0.0.0/0"' in fake.files[("main", tf_path)]
    assert fake.prs[0]["title"] == "🔒 PosturaNet: restrict SSH ingress on bastion SG (EC2.19)"

    # Same finding, same fix: no new writes, no duplicate PR (FR-28).
    writes = len(fake.writes)
    again = run_fix(str(sg_finding_path), tmp_repo, config, ctx)
    assert "PR already open" in again.stages[-1].summary
    assert len(fake.writes) == writes and len(fake.prs) == 1


def test_no_evidence_is_unknown(tmp_repo: Path, sg_finding_path: Path, tmp_path: Path) -> None:
    empty = tmp_path / "none.json"
    empty.write_text(json.dumps({"enis": ["eni-1"], "window": {"from": "2026-08-01T00:00:00Z", "to": "2026-10-29T00:00:00Z"}, "records": []}))  # fmt: skip
    config, _ = load_config(tmp_repo)
    record = run_fix(str(sg_finding_path), tmp_repo, config, _ctx(empty, mode="check"))
    assert record.result == "STOPPED" and record.exit_code == 3
    assert _status(record)["evidence"] is StageStatus.UNKNOWN
    assert record.why == "PosturaNet never changes a resource without usage evidence"


def test_low_confidence_stops_outside_dry_run(
    tmp_repo: Path, sg_finding_path: Path, tmp_path: Path
) -> None:
    start = datetime(2026, 10, 20, tzinfo=UTC)
    recs = [{"srcAddr": "10.0.4.12", "dstPort": "22", "protocol": "6", "hour": (start + timedelta(hours=h)).isoformat(), "n": "1"} for h in range(0, 9 * 24, 6)]  # fmt: skip
    short = tmp_path / "short.json"
    short.write_text(json.dumps({"enis": ["eni-1"], "window": {"from": start.isoformat(), "to": (start + timedelta(days=9)).isoformat()}, "records": recs}))  # fmt: skip
    config, _ = load_config(tmp_repo)
    record = run_fix(str(sg_finding_path), tmp_repo, config, _ctx(short, mode="check"))
    assert record.result == "STOPPED"
    assert "confidence low" in record.stages[-1 - 4].summary or any(
        "confidence low" in s.summary for s in record.stages
    )


def test_approved_contract_is_used_not_overwritten(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    config, _ = load_config(tmp_repo)
    run_fix(str(sg_finding_path), tmp_repo, config, _ctx(flows_path, mode="check"))
    path = tmp_repo / CONTRACT
    draft = load_contract(path)
    assert draft is not None
    approved = draft.model_copy(
        update={"status": "approved", "approved_by": "@alice", "needs_review": []}
    )
    write_contract(path, approved)
    text = path.read_text(encoding="utf-8")
    record = run_fix(str(sg_finding_path), tmp_repo, config, _ctx(flows_path, mode="check"))
    assert record.result == "VALIDATED"
    assert "approved contract" in next(s.summary for s in record.stages if s.name == "contract")
    assert path.read_text(encoding="utf-8") == text
    assert record.diff is not None and "198.51.100.23" not in record.diff.files[0].new_content


def test_state_drift_stops(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    state = tmp_repo / "state.fixture.json"
    doc = json.loads(state.read_text(encoding="utf-8"))
    doc["resources"][0]["instances"][0]["attributes"]["ingress"][0]["cidr_blocks"].append("192.168.0.0/16")  # fmt: skip
    state.write_text(json.dumps(doc), encoding="utf-8")
    config, _ = load_config(tmp_repo)
    record = run_fix(str(sg_finding_path), tmp_repo, config, _ctx(flows_path, mode="check"))
    assert record.result == "STOPPED"
    assert record.location is not None and record.location.drift is True


@pytest.mark.parametrize("missing", ["GITHUB_TOKEN", "repo"])
def test_open_pr_needs_token_and_repo(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path, missing: str
) -> None:
    config, _ = load_config(tmp_repo)
    env = (
        {"GITHUB_REPOSITORY": "acme/infra"} if missing == "GITHUB_TOKEN" else {"GITHUB_TOKEN": "x"}
    )
    record = run_fix(
        str(sg_finding_path), tmp_repo, config, _ctx(flows_path, mode="open-pr", env=env)
    )
    assert record.result == "STOPPED"
    assert _status(record)["deliver"] is StageStatus.FAIL
