"""FR-45a / golden rule 6: the opt-in outcome share sends five fields and nothing else."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from posturanet.cli.app import app
from posturanet.errors import UsageError
from posturanet.models import Outcome, OutcomeState, RunRecord
from posturanet.models.config import Config, load_config
from posturanet.outcome_share import SharedOutcome, record_for, share

ALLOWED = {"control", "fix_type", "outcome", "evidence_days", "agent_version"}
T0 = datetime(2026, 10, 30, 12, tzinfo=UTC)

# Every identifier a verify run can hold. None of these may ever be shared.
SECRETS = [
    "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a91f3c2",
    "123456789012",
    "sg-0a91f3c2",
    "aws_security_group.bastion",
    "acme/infra#412",
    "10.20.0.0/16",
    "203.0.113.7",
    "9f1c2d3e4b5a",
    "https://github.com/acme/infra/pull/413",
]


def _run(state: OutcomeState, **kw: object) -> RunRecord:
    outcome = Outcome(
        state=state,
        pr="acme/infra#412",
        finding_id=SECRETS[0],
        control=str(kw.pop("control", "EC2.19")),
        address="aws_security_group.bastion",
        fix_type=str(kw.pop("fix_type", "sg_ingress")),
        merged_at=T0,
        merge_sha="9f1c2d3e4b5a",
        watch_from=T0,
        watch_until=datetime(2026, 11, 2, 12, tzinfo=UTC),
        regressions=["203.0.113.7 → 22/tcp · 40 blocked (allowed by the contract)"],
        revert_pr="https://github.com/acme/infra/pull/413",
    )
    return RunRecord(
        agent_version="0.3.0",
        command="verify",
        target="acme/infra#412",
        mode="check",
        started_at=datetime(2026, 11, 3, tzinfo=UTC),
        result=state.value,
        result_detail="EC2.19 passes on aws_security_group.bastion (sg-0a91f3c2, 10.20.0.0/16)",
        why="arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a91f3c2",
        next_steps=["review 203.0.113.7"],
        outcome=outcome,
    )


def test_model_has_exactly_the_five_fields() -> None:
    # Widening this set widens golden rule 6: it needs a human yes and a PRD change first.
    assert set(SharedOutcome.model_fields) == ALLOWED
    rec, _ = record_for(_run(OutcomeState.CONFIRMED))
    assert rec is not None
    assert set(json.loads(rec.model_dump_json())) == ALLOWED
    with pytest.raises(ValidationError):
        SharedOutcome(**rec.model_dump(), resource_id="sg-0a91f3c2")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("state", "verdict"),
    [(OutcomeState.CONFIRMED, "held"), (OutcomeState.REGRESSED, "reverted")],
)
def test_record_has_no_identifiers(state: OutcomeState, verdict: str) -> None:
    rec, _ = record_for(_run(state))
    assert rec is not None
    assert rec.model_dump() == {
        "control": "EC2.19",
        "fix_type": "sg_ingress",
        "outcome": verdict,
        "evidence_days": 3,
        "agent_version": "0.3.0",
    }
    sent = rec.model_dump_json()
    for s in SECRETS:
        assert s not in sent


@pytest.mark.parametrize("state", [OutcomeState.APPLIED, OutcomeState.MERGED, OutcomeState.UNKNOWN])
def test_unfinished_runs_share_nothing(state: OutcomeState) -> None:
    rec, why = record_for(_run(state))
    assert rec is None and state.value in why


@pytest.mark.parametrize(
    ("kw", "why"),
    [
        ({"control": "acme-prod-bucket"}, "SERVICE.N"),
        ({"control": "EC2.19 sg-0a91f3c2"}, "SERVICE.N"),
        ({"fix_type": "None"}, "older PosturaNet"),
        ({"fix_type": "sg-0a91f3c2"}, "older PosturaNet"),
    ],
)
def test_odd_control_or_fix_type_is_not_shared(kw: dict[str, str], why: str) -> None:
    rec, reason = record_for(_run(OutcomeState.CONFIRMED, **kw))
    assert rec is None and why in reason


def test_share_posts_the_record() -> None:
    sent: list[tuple[str, bytes]] = []
    warning = share(
        _run(OutcomeState.CONFIRMED), "https://x.test/v1", lambda u, b: sent.append((u, b))
    )
    assert warning is None
    assert sent[0][0] == "https://x.test/v1"
    assert set(json.loads(sent[0][1])) == ALLOWED


@pytest.mark.parametrize(
    "exc", [httpx.ConnectTimeout("t"), httpx.ConnectError("no network"), OSError("dns")]
)
def test_share_failures_only_warn(exc: Exception) -> None:
    def boom(_url: str, _body: bytes) -> None:
        raise exc

    warning = share(_run(OutcomeState.CONFIRMED), "https://x.test/v1", boom)
    assert warning is not None and "not sent" in warning and "unchanged" in warning


def test_share_skips_unfinished_runs() -> None:
    def never(_url: str, _body: bytes) -> None:
        raise AssertionError("must not send")

    assert share(_run(OutcomeState.APPLIED), "https://x.test/v1", never) is None


def test_config_off_by_default_and_needs_endpoint(tmp_path: Path) -> None:
    assert Config().outcome_share.enabled is False
    assert Config().outcome_share.endpoint is None
    (tmp_path / ".posturanet.yml").write_text("outcome_share:\n  enabled: true\n")
    with pytest.raises(UsageError, match="outcome_share.endpoint"):
        load_config(tmp_path)
    (tmp_path / ".posturanet.yml").write_text(
        "outcome_share:\n  enabled: true\n  endpoint: http://x.test\n"
    )
    with pytest.raises(UsageError, match="endpoint"):
        load_config(tmp_path)


def test_preview_prints_exactly_what_would_be_sent(tmp_path: Path) -> None:
    done = tmp_path / "done.json"
    done.write_text(_run(OutcomeState.CONFIRMED).model_dump_json(), encoding="utf-8")
    watching = tmp_path / "watching.json"
    watching.write_text(_run(OutcomeState.APPLIED).model_dump_json(), encoding="utf-8")
    result = CliRunner().invoke(app, ["outcomes", "preview", str(done), str(watching)])
    assert result.exit_code == 0, result.output
    lines = result.stdout.strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == {
        "control": "EC2.19",
        "fix_type": "sg_ingress",
        "outcome": "held",
        "evidence_days": 3,
        "agent_version": "0.3.0",
    }
    assert "watching.json: nothing would be sent" in result.stderr


def test_preview_rejects_non_records(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    result = CliRunner().invoke(app, ["outcomes", "preview", str(bad)])
    assert result.exit_code == 2
