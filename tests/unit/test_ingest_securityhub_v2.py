"""Security Hub OCSF findings (get-findings-v2, EventBridge) and remediation plans (FR-4c)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from posturanet.aws.readonly import MutatingCallBlocked, ReadOnlyClient
from posturanet.aws.remediation_plans import pull_plans
from posturanet.cli.app import app
from posturanet.configfix.catalog import ConfigFix, fixes_for, merge
from posturanet.errors import StageStop
from posturanet.ingest import read_findings
from posturanet.ingest.ocsf import related_controls
from posturanet.ingest.plans import MARKER, choose_controls, parse_plan_item
from posturanet.models import FixType

FIX = Path(__file__).resolve().parents[1] / "fixtures"
V2 = FIX / "findings" / "securityhub_v2_findings.json"
PLANS = FIX / "findings" / "securityhub_plans.json"
SHA = "0" * 64
runner = CliRunner()


def _split(tmp_path: Path, path: Path) -> dict[str, Path]:
    out = tmp_path / "split"
    result = runner.invoke(app, ["findings", "split", str(path), "--out", str(out)])
    assert result.exit_code == 0, result.output
    return {p.name.split("-", 1)[0]: p for p in out.iterdir()}


# --- Security Hub OCSF findings


def test_get_findings_v2_output_is_read_as_ocsf() -> None:
    found = read_findings(V2)
    assert found.format == "ocsf"  # {"Findings": [...]} is ASFF's key too
    assert [e.control_id for e in found.fixable] == ["EC2.13", "RDS.8"]
    hub = found.fixable[0].finding
    assert hub is not None
    assert (hub.source, hub.resource.id, hub.resource.account) == (
        "security hub",
        "sg-0a91f3c2",
        "123456789012",
    )


def test_passed_control_finding_is_not_fixed() -> None:
    entry = read_findings(V2).entries[2]
    assert entry.finding is None
    assert "control result is PASS" in (entry.reason or "")


def test_exposure_finding_points_to_its_control_findings() -> None:
    entry = read_findings(V2).entries[3]
    assert entry.finding is None
    assert "exposure finding" in (entry.reason or "")
    assert "PosturaNet fixes RDS.8" in (entry.reason or "")


def test_eventbridge_event_is_unwrapped(tmp_path: Path) -> None:
    findings = json.loads(V2.read_text("utf-8"))["Findings"]
    event = {
        "detail-type": "Findings Imported V2",
        "source": "aws.securityhub",
        "detail": {"findings": [findings[1]]},
    }
    p = tmp_path / "event.json"
    p.write_text(json.dumps(event), encoding="utf-8")
    found = read_findings(p)
    assert (found.format, [e.control_id for e in found.fixable]) == ("ocsf", ["RDS.8"])


def test_related_controls_reads_titles_in_order() -> None:
    item = {
        "finding_info": {
            "related_events": [
                {"type": "ResourceConfiguration", "title": "AWS::IAM::User x"},
                {"type": "Finding", "title": "IAM.5 MFA should be enabled"},
                {"type": "Finding", "title": "IAM.7 Password policies"},
                {"type": "Finding", "title": "IAM.5 MFA should be enabled"},
                {"type": "Finding", "title": "not a control"},
            ]
        }
    }
    assert related_controls(item) == ["IAM.5", "IAM.7"]


def test_security_hub_finding_gets_a_settings_fix(tmp_path: Path) -> None:
    split = _split(tmp_path, V2)
    repo = FIX / "tf" / "config"
    out = runner.invoke(app, ["fix", str(split["RDS.8"]), "--dry-run", "--repo", str(repo)])
    assert out.exit_code == 0, out.output
    assert "security hub RDS.8" in out.output
    assert "+  deletion_protection = true" in out.output


# --- remediation plans


def test_plans_file_lists_one_finding_per_plan() -> None:
    found = read_findings(PLANS)
    assert found.format == "plan"
    assert [e.control_id for e in found.entries] == ["RDS.2+RDS.8", "EC2.13", None, None]
    assert "Resolved" in (found.entries[2].reason or "")
    assert "IAM.5, none of which" in (found.entries[3].reason or "")


def test_plan_finding_carries_the_plan_and_its_resource() -> None:
    f = found_plan(0)
    assert f.finding_id == "rt-00000000000000000000000000000001"
    assert (f.resource.id, f.resource.arn) == (
        "orders",
        "arn:aws:rds:us-east-1:123456789012:db:orders",
    )
    assert f.fix_type is FixType.CONFIG_ATTRIBUTE
    assert f.title == "Make the DB instance private and turn on deletion protection"
    assert f.provenance.schema_name == "securityhub-remediation-v2"


def test_evidence_fix_runs_alone_and_names_the_rest() -> None:
    f = found_plan(1)
    assert f.control_id == "EC2.13"
    assert f.title.endswith("(also linked, fix separately: EC2.19)")


def found_plan(index: int) -> Any:
    finding = read_findings(PLANS).entries[index].finding
    assert finding is not None
    return finding


def test_plan_without_exposure_findings_asks_for_a_pull() -> None:
    item = json.loads(PLANS.read_text("utf-8"))["Plans"][0]
    del item["ExposureFindings"]
    with pytest.raises(StageStop, match="no exposure findings"):
        parse_plan_item(item, raw_sha256=SHA)


def test_bare_get_remediations_output_is_recognized(tmp_path: Path) -> None:
    plan = json.loads(PLANS.read_text("utf-8"))["Plans"][0]
    bare = {k: v for k, v in plan.items() if k not in ("Exposures", "ExposureFindings")}
    p = tmp_path / "raw.json"
    p.write_text(json.dumps({"Items": [bare]}), encoding="utf-8")
    found = read_findings(p)
    assert found.format == "plan"
    assert "findings pull-plans" in (found.entries[0].reason or "")


def test_choose_controls_groups_by_resource_type() -> None:
    assert choose_controls(["RDS.2", "RDS.8", "IAM.5"]) == (["RDS.2", "RDS.8"], [])
    # DynamoDB.2 fits another resource type: fixed separately.
    assert choose_controls(["RDS.8", "RDS.10", "DynamoDB.2"]) == (
        ["RDS.8", "RDS.10"],
        ["DynamoDB.2"],
    )
    assert choose_controls(["EC2.13", "EC2.19"]) == (["EC2.13"], ["EC2.19"])
    assert choose_controls(["IAM.5"]) == ([], [])


def test_combined_control_is_one_merged_row() -> None:
    rows = fixes_for("RDS.2+RDS.8")
    assert [r.resource_type for r in rows] == ["aws_db_instance"]
    row = rows[0]
    assert row.control == "RDS.2+RDS.8"
    assert [c.path for c in row.changes] == ["publicly_accessible", "deletion_protection"]
    assert row.risk == "medium"  # the riskier part wins
    assert fixes_for("RDS.8+IAM.5") == []  # IAM.5 has no row


def test_conflicting_rows_do_not_merge() -> None:
    base = fixes_for("RDS.8")[0]
    other = ConfigFix.model_validate(
        {
            **base.model_dump(),
            "control": "X.1",
            "changes": [{**base.changes[0].model_dump(), "value": False}],
        }
    )
    assert merge([base, other]) is None


def test_combined_plan_is_one_change_on_one_resource(tmp_path: Path) -> None:
    split = _split(tmp_path, PLANS)
    repo = FIX / "tf" / "config"
    out = runner.invoke(app, ["fix", str(split["RDS.2_RDS.8"]), "--dry-run", "--repo", str(repo)])
    assert out.exit_code == 0, out.output
    assert "security hub plan RDS.2+RDS.8" in out.output
    assert "+  publicly_accessible = false" in out.output
    assert "+  deletion_protection = true" in out.output
    assert "Ignore previous instructions" not in out.output  # AWS guidance is data only


# --- pulling plans (no AWS: a fake client behind the read-only wrapper)


class FakeSecurityHub:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        plans = json.loads(PLANS.read_text("utf-8"))["Plans"]
        self._items = [
            {k: v for k, v in p.items() if k not in ("Exposures", "ExposureFindings")}
            for p in plans
        ]
        self._items[0]["UpdatedAt"] = datetime(2026, 10, 28, 8, 0, tzinfo=UTC)
        self._exposures = {p["TargetUid"]: p["Exposures"] for p in plans}
        self._findings = {f["metadata"]["uid"]: f for p in plans for f in p["ExposureFindings"]}

    def get_remediations_v2(self, **kw: Any) -> dict[str, Any]:
        self.calls.append(("get_remediations_v2", kw))
        start = int(kw.get("NextToken") or 0)
        page = self._items[start : start + 2]
        nxt = start + 2
        return {"Items": page, **({"NextToken": str(nxt)} if nxt < len(self._items) else {})}

    def list_exposures_by_remediation_v2(self, **kw: Any) -> dict[str, Any]:
        self.calls.append(("list_exposures_by_remediation_v2", kw))
        return {"Items": self._exposures[kw["TargetUid"]], "TargetUid": kw["TargetUid"]}

    def get_findings_v2(self, **kw: Any) -> dict[str, Any]:
        self.calls.append(("get_findings_v2", kw))
        uids = [s["Filter"]["Value"] for s in kw["Filters"]["CompositeFilters"][0]["StringFilters"]]
        return {"Findings": [self._findings[u] for u in uids if u in self._findings]}

    def batch_update_findings_v2(self, **kw: Any) -> None:  # pragma: no cover - must be blocked
        raise AssertionError("a write reached the client")


def test_pull_writes_plans_posturanet_can_read(tmp_path: Path) -> None:
    fake = FakeSecurityHub()
    doc = pull_plans(
        ReadOnlyClient(fake, "securityhub"),
        now=datetime(2026, 10, 28, 9, 0, tzinfo=UTC),
        region="us-east-1",
        max_plans=10,
    )
    assert doc[MARKER] == "1" and doc["PulledAt"] == "2026-10-28T09:00:00Z"
    assert len(doc["Plans"]) == 4  # two pages
    assert doc["Plans"][0]["UpdatedAt"] == "2026-10-28T08:00:00Z"
    first = fake.calls[0][1]
    assert (first["ShowGuidance"], first["GuidanceFormat"]) == (True, "Terraform")
    p = tmp_path / "plans.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert [e.control_id for e in read_findings(p).fixable] == ["RDS.2+RDS.8", "EC2.13"]


def test_pull_respects_max_and_priority() -> None:
    fake = FakeSecurityHub()
    doc = pull_plans(
        ReadOnlyClient(fake, "securityhub"),
        now=datetime.now(UTC),
        region=None,
        max_plans=1,
        priority="High",
    )
    assert len(doc["Plans"]) == 1
    kw = fake.calls[0][1]
    assert kw["MaxResults"] == 1
    assert kw["Filters"]["CompositeFilters"][0]["StringFilters"][0]["FieldName"] == "Priority"


def test_plan_reads_are_allowlisted_and_writes_are_not() -> None:
    client = ReadOnlyClient(FakeSecurityHub(), "securityhub")
    for name in ("get_remediations_v2", "list_exposures_by_remediation_v2", "get_findings_v2"):
        assert callable(getattr(client, name))
    with pytest.raises(MutatingCallBlocked):
        _ = client.batch_update_findings_v2
