from __future__ import annotations

import ipaddress
import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from fakes import ConfigTerraform, FakeGitHub, FakeTerraform, ingress_json
from posturanet.deliver import GitHub
from posturanet.deliver.idempotency import spec_in
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.models import OutcomeState, VerifySpec
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix
from posturanet.synth.sg_rules import Rule
from posturanet.verify import VerifyContext, parse_pr_ref, run_verify
from posturanet.verify.signals import RejectFile

FIXTURES = Path(__file__).parent.parent / "fixtures"
SG_TF = "modules/bastion/main.tf"
SG_CONTRACT = "posturanet/contracts/module.bastion.aws_security_group.this.yaml"


def _at(text: str) -> Callable[[], datetime]:
    return lambda: datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def _state_with(src: Path, dst: Path, address: str, attrs: dict[str, Any]) -> Path:
    state = json.loads(src.read_text(encoding="utf-8"))
    for res in state["resources"]:
        full = ".".join(p for p in (res.get("module", ""), res["type"], res["name"]) if p)
        if full == address:
            res["instances"][0]["attributes"].update(attrs)
    dst.write_text(json.dumps(state), encoding="utf-8")
    return dst


def _rejects(tmp: Path, rows: list[dict[str, Any]]) -> RejectFile:
    path = tmp / "rejects.json"
    path.write_text(json.dumps({"records": rows}), encoding="utf-8")
    return RejectFile(path)


# --- security group fix


@pytest.fixture
def sg_merged(tmp_repo: Path, flows_path: Path, sg_finding_path: Path, tmp_path: Path) -> Any:
    config, _ = load_config(tmp_repo)
    fake = FakeGitHub({SG_TF: (tmp_repo / SG_TF).read_text(encoding="utf-8")})
    gh = GitHub("t", "acme/infra", fake.client())
    ctx = Context(
        mode="open-pr", evidence=FileSource(flows_path), terraform=FakeTerraform(), github=gh
    )
    record = run_fix(str(sg_finding_path), tmp_repo, config, ctx)
    assert record.result == "OPENED", record.stages
    spec = spec_in(fake.prs[0]["body"])
    assert spec is not None and spec.fix_type == "sg_ingress" and spec.must_allow
    original = fake.files[("main", SG_TF)]
    fake.merge(412)
    state = _state_with(
        tmp_repo / "state.fixture.json",
        tmp_path / "applied.json",
        spec.address,
        {"ingress": ingress_json([Rule(*r) for r in spec.rules])},
    )
    return config, fake, gh, spec, state, original


def _sg_ctx(sg: Any, now: str, rejects: RejectFile, **kw: Any) -> VerifyContext:
    _, _, gh, _, state, _ = sg
    return VerifyContext(github=gh, clock=_at(now), state_path=state, rejects=rejects, **kw)


def test_sg_watching_then_confirmed(sg_merged: Any, tmp_repo: Path, tmp_path: Path) -> None:
    config = sg_merged[0]
    rejects = _rejects(tmp_path, [])
    mid = run_verify(
        "acme/infra#412", tmp_repo, config, _sg_ctx(sg_merged, "2026-10-31T12:00:00Z", rejects)
    )
    assert mid.result == "WATCHING", mid.stages
    assert mid.exit_code == 0 and mid.outcome is not None
    assert mid.outcome.state is OutcomeState.APPLIED
    assert "re-run verify after 2026-11-02 12:00 UTC" in mid.next_steps[0]

    done = run_verify(
        "acme/infra#412", tmp_repo, config, _sg_ctx(sg_merged, "2026-11-03T00:00:00Z", rejects)
    )
    assert done.result == "CONFIRMED", done.stages
    assert done.outcome is not None and done.outcome.state is OutcomeState.CONFIRMED


def _blocked_row(spec: VerifySpec, hour: str = "2026-10-31T03:00:00Z") -> dict[str, Any]:
    cidr, port, proto = spec.must_allow[0]
    ip = str(next(iter(ipaddress.ip_network(cidr, strict=False))))
    return {"srcAddr": ip, "dstPort": port, "protocol": proto, "hour": hour, "n": 40}


def test_sg_regression_without_open_pr(sg_merged: Any, tmp_repo: Path, tmp_path: Path) -> None:
    config, fake, _, spec, _, _ = sg_merged
    rejects = _rejects(tmp_path, [_blocked_row(spec)])
    record = run_verify(
        "acme/infra#412", tmp_repo, config, _sg_ctx(sg_merged, "2026-11-03T00:00:00Z", rejects)
    )
    assert record.result == "REGRESSED" and record.exit_code == 4
    assert record.outcome is not None and record.outcome.regressions
    assert "40 blocked" in record.outcome.regressions[0]
    assert record.next_steps == ["re-run with --open-pr to open the revert PR"]
    assert len(fake.prs) == 1  # nothing opened without --open-pr


def test_sg_rejects_outside_the_contract_are_not_regressions(
    sg_merged: Any, tmp_repo: Path, tmp_path: Path
) -> None:
    config, _, _, spec, _, _ = sg_merged
    stranger = {**_blocked_row(spec), "srcAddr": "198.51.100.77"}
    before_apply = _blocked_row(spec, hour="2026-10-29T00:00:00Z")
    rejects = _rejects(tmp_path, [stranger, before_apply])
    record = run_verify(
        "acme/infra#412", tmp_repo, config, _sg_ctx(sg_merged, "2026-11-03T00:00:00Z", rejects)
    )
    assert record.result == "CONFIRMED", record.stages


def test_revert_pr_restores_files(sg_merged: Any, tmp_repo: Path, tmp_path: Path) -> None:
    config, fake, _, spec, _, original = sg_merged
    rejects = _rejects(tmp_path, [_blocked_row(spec)])
    ctx = _sg_ctx(sg_merged, "2026-11-03T00:00:00Z", rejects, open_pr=True)
    record = run_verify("acme/infra#412", tmp_repo, config, ctx)
    assert record.result == "REGRESSED", record.stages
    assert record.pr_url == "https://github.com/acme/infra/pull/413"
    revert = fake.prs[1]
    branch = revert["head"]["ref"]
    assert branch.startswith("posturanet/revert/")
    assert fake.files[(branch, SG_TF)] == original
    assert (branch, SG_CONTRACT) not in fake.files  # added by the fix PR, so removed
    assert revert["title"].startswith("↩️ PosturaNet: revert #412")
    assert "40 blocked" in revert["body"]

    # Same regression again: the open revert PR is reused, not duplicated.
    again = run_verify("acme/infra#412", tmp_repo, config, ctx)
    assert again.result == "REGRESSED" and len(fake.prs) == 2


def test_revert_stops_when_file_changed_after_merge(
    sg_merged: Any, tmp_repo: Path, tmp_path: Path
) -> None:
    config, fake, _, spec, _, _ = sg_merged
    fake.files[("main", SG_TF)] += "\n# later change\n"
    rejects = _rejects(tmp_path, [_blocked_row(spec)])
    ctx = _sg_ctx(sg_merged, "2026-11-03T00:00:00Z", rejects, open_pr=True)
    record = run_verify("acme/infra#412", tmp_repo, config, ctx)
    assert record.result == "STOPPED" and record.exit_code == 3
    assert "changed on main after #412 merged" in record.stages[-1].summary or any(
        "changed on main" in s.summary for s in record.stages
    )
    assert len(fake.prs) == 1


def test_sg_not_applied(sg_merged: Any, tmp_repo: Path, tmp_path: Path) -> None:
    config, _, gh, _, _, _ = sg_merged
    ctx = VerifyContext(
        github=gh,
        clock=_at("2026-11-03T00:00:00Z"),
        state_path=tmp_repo / "state.fixture.json",  # still the open rule
        rejects=_rejects(tmp_path, []),
    )
    record = run_verify("acme/infra#412", tmp_repo, config, ctx)
    assert record.result == "NOT APPLIED" and record.exit_code == 3


def test_watch_needs_a_signal(sg_merged: Any, tmp_repo: Path) -> None:
    config, _, gh, _, state, _ = sg_merged
    ctx = VerifyContext(github=gh, clock=_at("2026-11-03T00:00:00Z"), state_path=state)
    record = run_verify("acme/infra#412", tmp_repo, config, ctx)
    assert record.result == "STOPPED" and record.exit_code == 3
    assert record.outcome is not None and record.outcome.state is OutcomeState.UNKNOWN


# --- attribute fix


@pytest.fixture
def config_repo(tmp_path: Path) -> Path:
    out = tmp_path / "repo"
    shutil.copytree(FIXTURES / "tf" / "config", out)
    return out


def test_config_fix_confirmed_from_state(config_repo: Path, tmp_path: Path) -> None:
    config, _ = load_config(config_repo)
    fake = FakeGitHub({"main.tf": (config_repo / "main.tf").read_text(encoding="utf-8")})
    gh = GitHub("t", "acme/infra", fake.client())
    tf = ConfigTerraform(
        "aws_db_instance.orders",
        "aws_db_instance",
        ["deletion_protection"],
        before={"deletion_protection": False},
    )
    finding = str(FIXTURES / "findings" / "rds_deletion_protection.json")
    opened = run_fix(finding, config_repo, config, Context(mode="open-pr", terraform=tf, github=gh))
    assert opened.result == "OPENED", opened.stages

    open_ctx = VerifyContext(github=gh, clock=_at("2026-10-30T00:00:00Z"))
    pending = run_verify("acme/infra#412", config_repo, config, open_ctx)
    assert pending.result == "OPENED" and pending.exit_code == 0

    fake.merge(412)
    not_yet = run_verify("acme/infra#412", config_repo, config, open_ctx)
    assert not_yet.result == "NOT APPLIED", not_yet.stages
    assert "deletion_protection is None" in not_yet.stages[1].summary

    state = _state_with(
        config_repo / "state.fixture.json",
        tmp_path / "applied.json",
        "aws_db_instance.orders",
        {"deletion_protection": True},
    )
    ctx = VerifyContext(github=gh, clock=_at("2026-10-30T13:00:00Z"), state_path=state)
    record = run_verify("acme/infra#412", config_repo, config, ctx)
    assert record.result == "CONFIRMED", record.stages
    assert {s.name: s.status.value for s in record.stages}["watch"] == "skipped"


def test_closed_without_merge_is_rejected(config_repo: Path) -> None:
    config, _ = load_config(config_repo)
    fake = FakeGitHub({"main.tf": (config_repo / "main.tf").read_text(encoding="utf-8")})
    gh = GitHub("t", "acme/infra", fake.client())
    tf = ConfigTerraform("aws_db_instance.orders", "aws_db_instance", ["deletion_protection"])
    finding = str(FIXTURES / "findings" / "rds_deletion_protection.json")
    run_fix(finding, config_repo, config, Context(mode="open-pr", terraform=tf, github=gh))
    fake.prs[0]["state"] = "closed"
    record = run_verify("acme/infra#412", config_repo, config, VerifyContext(github=gh))
    assert record.result == "REJECTED"


def test_pr_without_spec_stops(config_repo: Path) -> None:
    config, _ = load_config(config_repo)
    fake = FakeGitHub({})
    fake.prs.append({"number": 7, "body": "hand-written PR", "state": "open", "head": {"ref": "x"}})
    gh = GitHub("t", "acme/infra", fake.client())
    record = run_verify("acme/infra#7", config_repo, config, VerifyContext(github=gh))
    assert record.result == "STOPPED"
    assert "no PosturaNet verify spec" in record.stages[0].summary


@pytest.mark.parametrize(
    ("ref", "want"),
    [
        ("https://github.com/acme/infra/pull/12", ("acme/infra", 12)),
        ("https://github.com/acme/infra/pull/12/files", ("acme/infra", 12)),
        ("acme/infra#12", ("acme/infra", 12)),
        ("12", ("acme/default", 12)),
    ],
)
def test_parse_pr_ref(ref: str, want: tuple[str, int]) -> None:
    assert parse_pr_ref(ref, "acme/default") == want


def test_parse_pr_ref_needs_a_repo() -> None:
    with pytest.raises(StageStop):
        parse_pr_ref("12", None)


class _Hub:
    def __init__(self, status: str, updated: str) -> None:
        self.status, self.updated = status, updated

    def get_findings(self, **_: Any) -> dict[str, Any]:
        return {"Findings": [{"Compliance": {"Status": self.status}, "UpdatedAt": self.updated}]}


class _Aws:
    """Only Security Hub; state comes from --state, so no S3 call is made."""

    def __init__(self, hub: _Hub) -> None:
        self.hub = hub

    def __call__(self, service: str) -> Any:
        assert service == "securityhub", service
        return self.hub


@pytest.mark.parametrize(
    ("status", "updated", "result"),
    [
        ("PASSED", "2026-10-31T00:00:00Z", "CONFIRMED"),
        ("FAILED", "2026-10-29T00:00:00Z", "CONFIRMED"),  # not re-evaluated since apply yet
        ("FAILED", "2026-10-31T00:00:00Z", "STILL FAILING"),
    ],
)
def test_security_hub_status(
    sg_merged: Any, tmp_repo: Path, tmp_path: Path, status: str, updated: str, result: str
) -> None:
    config = sg_merged[0]
    ctx = _sg_ctx(sg_merged, "2026-11-03T00:00:00Z", _rejects(tmp_path, []))
    ctx.aws = _Aws(_Hub(status, updated))  # type: ignore[assignment]
    ctx.rejects = _rejects(tmp_path, [])
    record = run_verify("acme/infra#412", tmp_repo, config, ctx)
    assert record.result == result, record.stages
