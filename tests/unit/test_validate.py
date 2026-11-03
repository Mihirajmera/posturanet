from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fakes import TARGET, FakeTerraform, plan_for
from posturanet.contracts import build_contract
from posturanet.evidence import FileSource, aggregate
from posturanet.ingest import ingest
from posturanet.locate import locate
from posturanet.models import CheckResult, NetRule, ReportStatus
from posturanet.models.config import load_config
from posturanet.synth import make_diff, parse_security_group, synthesize
from posturanet.synth.sg_rules import Rule
from posturanet.validate import ValidationInputs, validate
from posturanet.validate.invariants import allow_holds, deny_holds
from posturanet.validate.plan_scope import check_scope
from posturanet.validate.recheck import recheck

OPEN_22 = Rule("0.0.0.0/0", 22, 22, "tcp")
VPN = Rule("10.0.4.0/24", 22, 22, "tcp")


def test_plan_scope_pass() -> None:
    assert check_scope(plan_for([OPEN_22], [VPN]), TARGET).result is CheckResult.PASS


def test_plan_scope_other_resource_fails() -> None:
    extra = [{"address": "aws_instance.bastion", "change": {"actions": ["delete", "create"]}}]
    check = check_scope(plan_for([OPEN_22], [VPN], extra=extra), TARGET)
    assert check.result is CheckResult.FAIL
    assert "aws_instance.bastion (delete/create)" in check.detail


def test_plan_scope_replace_fails() -> None:
    check = check_scope(plan_for([OPEN_22], [VPN], actions=["delete", "create"]), TARGET)
    assert check.result is CheckResult.FAIL and "not updated in place" in check.detail


def test_plan_scope_ignores_noop_and_reads() -> None:
    extra = [
        {"address": "aws_vpc.main", "change": {"actions": ["no-op"]}},
        {"address": "data.aws_caller_identity.me", "change": {"actions": ["read"]}},
    ]
    assert check_scope(plan_for([OPEN_22], [VPN], extra=extra), TARGET).result is CheckResult.PASS


def test_recheck_controls() -> None:
    assert recheck("EC2.19", [OPEN_22])[0] is False
    assert recheck("EC2.19", [VPN])[0] is True
    assert recheck("EC2.13", [Rule("0.0.0.0/0", 0, 65535, "tcp")])[0] is False
    assert recheck("EC2.14", [OPEN_22])[0] is True  # 3389 only
    assert recheck("EC2.54", [Rule("::/0", 22, 22, "tcp")])[0] is False
    assert recheck("EC2.53", [Rule("::/0", 22, 22, "tcp")])[0] is True  # IPv4 only
    assert recheck("EC2.18", [Rule("0.0.0.0/0", 443, 443, "tcp")])[0] is True
    assert recheck("EC2.18", [Rule("0.0.0.0/0", 0, 0, "-1")])[0] is False


def test_invariants_allow_and_deny() -> None:
    src = NetRule(cidr="10.0.4.0/25", port=22, proto="tcp")
    assert allow_holds([VPN], src)
    assert not allow_holds([Rule("10.0.4.0/26", 22, 22, "tcp")], src)  # half of the /25
    assert not allow_holds([Rule("10.0.4.0/24", 23, 23, "tcp")], src)
    world = NetRule(cidr="0.0.0.0/0", port=22, proto="tcp")
    assert not deny_holds([OPEN_22], world)
    assert not deny_holds([Rule("0.0.0.0/1", 0, 0, "-1")], world)
    assert deny_holds([VPN, Rule("0.0.0.0/0", 443, 443, "tcp")], world)


def _inputs(repo: Path, flows: Path, finding: Path) -> ValidationInputs:
    config, _ = load_config(repo)
    f = ingest(str(finding))
    loc = locate(f, repo, config)
    sg = parse_security_group(repo / loc.file, loc.line, "aws_security_group", "this")
    now = datetime.now(UTC)
    obs = aggregate(FileSource(flows).fetch("sg", now, now), loc.address)
    contract = build_contract(obs, [OPEN_22], account=None, region=None)
    synth = synthesize(contract, sg.rules(), config.synthesis)
    diff = make_diff(repo, sg, synth, loc.address)
    return ValidationInputs(repo, f, loc, diff, contract, synth, config)


def test_offline_is_incomplete(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    report = validate(_inputs(tmp_repo, flows_path, sg_finding_path), FakeTerraform(), offline=True)
    assert report.status is ReportStatus.INCOMPLETE
    by_id = {c.id: c for c in report.checks}
    assert by_id["plan_scope"].result is CheckResult.SKIPPED
    assert by_id["invariants"].result is CheckResult.PASS
    assert by_id["recheck"].result is CheckResult.PASS
    assert by_id["invariants"].model_scope


def test_full_validation_passes(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    tf = FakeTerraform()
    report = validate(_inputs(tmp_repo, flows_path, sg_finding_path), tf, offline=False)
    assert report.status is ReportStatus.PASS, report.checks
    assert {"fmt", "init", "validate", "plan"} <= set(tf.calls)
    ids = [c.id for c in report.checks if c.required]
    assert ids == ["guardrails", "fmt", "validate", "plan_scope", "drift", "plan_matches", "invariants", "recheck"]  # fmt: skip


def test_drift_in_plan_fails(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    tf = FakeTerraform(live_before=[OPEN_22, Rule("192.168.9.0/24", 22, 22, "tcp")])
    report = validate(_inputs(tmp_repo, flows_path, sg_finding_path), tf, offline=False)
    assert report.status is ReportStatus.FAIL
    assert next(c for c in report.checks if c.id == "drift").result is CheckResult.FAIL


def test_unrelated_plan_change_fails(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    extra = [{"address": "aws_instance.bastion", "change": {"actions": ["update"]}}]
    tf = FakeTerraform(extra_changes=extra)
    report = validate(_inputs(tmp_repo, flows_path, sg_finding_path), tf, offline=False)
    assert report.status is ReportStatus.FAIL


def test_missing_terraform_is_incomplete(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    tf = FakeTerraform(available=False)
    report = validate(_inputs(tmp_repo, flows_path, sg_finding_path), tf, offline=True)
    assert next(c for c in report.checks if c.id == "fmt").result is CheckResult.SKIPPED
    assert report.status is ReportStatus.INCOMPLETE


def test_guardrail_paths(tmp_repo: Path, flows_path: Path, sg_finding_path: Path) -> None:
    inputs = _inputs(tmp_repo, flows_path, sg_finding_path)
    inputs.config.validation.allowed_paths = ["infra/**"]
    report = validate(inputs, FakeTerraform(), offline=False)
    assert report.status is ReportStatus.FAIL
    assert report.checks[0].id == "guardrails" and report.checks[0].result is CheckResult.FAIL
