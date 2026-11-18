"""CDK attribute fixes (property overrides on the L2 construct) and IaC scanner findings on a
CDK app's synthesized templates."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from posturanet.aws.readonly import ReadOnlyClient
from posturanet.cdk import source
from posturanet.errors import StageStop
from posturanet.evidence import FileSource
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix, run_fix_full

FIX = Path(__file__).resolve().parents[1] / "fixtures"
TS = FIX / "cdk" / "ts-app"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
TABLE = "DynamoDB.6:events"
TRIVY = FIX / "cdk" / "scanners" / "trivy_cdk.json"


@pytest.fixture
def ts(tmp_path: Path) -> Path:
    dst = tmp_path / "ts-app"
    shutil.copytree(TS, dst)
    return dst


class Synth:
    """`cdk synth` stand-in: the fixture assembly, with the table's override applied when the
    edited source has one."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo

    def synth(self, app: Path, out: Path) -> str | None:
        shutil.copytree(self.repo / "cdk.out", out, dirs_exist_ok=True)
        if "addPropertyOverride('DeletionProtectionEnabled', true)" in (
            app / "lib/storage-stack.ts"
        ).read_text("utf-8"):
            path = out / "storage.template.json"
            doc = json.loads(path.read_text("utf-8"))
            doc["Resources"]["Events1A2B3C4D"]["Properties"]["DeletionProtectionEnabled"] = True
            path.write_text(json.dumps(doc), "utf-8")
        return None


def _aws(repo: Path, template: str) -> Any:
    body = json.loads((repo / "cdk.out" / template).read_text("utf-8"))

    class Fake:
        def get_template(self, **kw: Any) -> dict[str, Any]:
            return {"TemplateBody": body}

        def describe_stack_resources(self, **kw: Any) -> dict[str, Any]:
            data: dict[str, Any] = json.loads((repo / "stack-resources.json").read_text("utf-8"))
            return data

        def describe_security_groups(self, **kw: Any) -> dict[str, Any]:
            perms = [
                {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": c}]}
                for p, c in [(22, "0.0.0.0/0"), (9100, "10.0.0.0/16")]
            ]
            return {"SecurityGroups": [{"GroupId": "sg-0a91f3c2", "IpPermissions": perms}]}

    return lambda service: ReadOnlyClient(Fake(), service)


def test_attribute_fix_overrides_the_l2_default_child(ts: Path) -> None:
    original = (ts / "lib/storage-stack.ts").read_bytes()
    ctx = Context(mode="check", aws=_aws(ts, "storage.template.json"), cdk=Synth(ts))
    record = run_fix(TABLE, ts, load_config(ts)[0], ctx)
    assert record.result == "VALIDATED", record.stages
    assert record.location is not None
    assert (record.location.address, record.location.line) == ("cdk.storage.Events1A2B3C4D", 16)
    assert record.diff is not None
    added = [ln for ln in record.diff.files[0].unified_diff.splitlines() if ln.startswith("+ ")]
    assert added == [
        "+    (events.node.defaultChild as dynamodb.CfnTable)"
        ".addPropertyOverride('DeletionProtectionEnabled', true);"
    ]
    checks = {c.id: c.result.value for c in record.validation.checks}  # type: ignore[union-attr]
    assert checks["source"] == checks["cdk_synth"] == checks["recheck"] == "pass"
    assert checks["template_scope"] == checks["drift"] == "pass"
    assert (ts / "lib/storage-stack.ts").read_bytes() == original


def test_attribute_fix_fails_when_synth_ignores_the_override(ts: Path) -> None:
    class Unchanged(Synth):
        def synth(self, app: Path, out: Path) -> str | None:
            shutil.copytree(self.repo / "cdk.out", out, dirs_exist_ok=True)
            return None

    ctx = Context(mode="check", aws=_aws(ts, "storage.template.json"), cdk=Unchanged(ts))
    record = run_fix(TABLE, ts, load_config(ts)[0], ctx)
    assert record.result == "STOPPED" and record.exit_code == 4
    checks = {c.id: c.result.value for c in record.validation.checks}  # type: ignore[union-attr]
    assert checks["template_scope"] == "fail" and checks["recheck"] == "fail"


@pytest.mark.parametrize(
    ("old", "new", "says"),
    [
        ("const events = new dynamodb.Table(", "new dynamodb.Table(", "assigned to a variable"),
        ("    events.grantReadData(", "    (events.node.defaultChild as dynamodb.CfnTable)"
         ".addPropertyOverride('DeletionProtectionEnabled', false);\n    events.grantReadData(",
         "existing property override of DeletionProtectionEnabled"),
    ],
)  # fmt: skip
def test_attribute_fix_stops_unknown(ts: Path, old: str, new: str, says: str) -> None:
    f = ts / "lib/storage-stack.ts"
    f.write_text(f.read_text("utf-8").replace(old, new, 1), "utf-8")
    record = run_fix(TABLE, ts, load_config(ts)[0], Context())
    stop = next(s for s in record.stages if s.status.value == "unknown")
    assert stop.name == "fix" and says in stop.summary, stop.summary


def test_python_override_renders_snake_case(tmp_path: Path) -> None:
    f = tmp_path / "s.py"
    text = (
        'queue = sqs.Queue(\n    self, "Jobs", retention_period=Duration.days(4)\n)\nnext_line()\n'
    )
    (c,) = source.scan(f, text, "Jobs", "Queue")
    new = source.render_attr(c, [("SqsManagedSseEnabled", True), ("Tags", ["a"])], "CfnQueue")
    assert new == (
        'queue = sqs.Queue(\n    self, "Jobs", retention_period=Duration.days(4)\n)\n'
        'queue.node.default_child.add_property_override("SqsManagedSseEnabled", True)\n'
        'queue.node.default_child.add_property_override("Tags", ["a"])\n'
        "next_line()\n"
    )
    with pytest.raises(StageStop, match="existing property override"):
        source.render_attr(source.rescan(c, new), [("SqsManagedSseEnabled", True)], "CfnQueue")


def test_trivy_template_finding_on_a_cdk_app_runs_the_sg_fix(ts: Path) -> None:
    ctx = Context(evidence=FileSource(FIX / "flows/bastion_90d.json"), clock=lambda: NOW)
    record, proposal = run_fix_full(str(TRIVY), ts, load_config(ts)[0], ctx)
    assert record.result == "DRY RUN", record.stages
    assert record.finding is not None and record.finding.resource.id == "sg-0a91f3c2"
    assert record.finding.resource.address == "cdk.network.BastionSg1A2B3C4D"
    assert (
        proposal is not None and "Peer.ipv4('10.0.4.12/32')" in proposal.diff.files[0].new_content
    )


def test_template_finding_outside_the_assembly_stops_unknown(ts: Path) -> None:
    report = json.loads(TRIVY.read_text("utf-8"))
    report["Results"][0]["Target"] = "templates/network.yaml"
    path = ts / "trivy.json"
    path.write_text(json.dumps(report), "utf-8")
    record = run_fix(str(path), ts, load_config(ts)[0], Context())
    stop = next(s for s in record.stages if s.status.value == "unknown")
    assert stop.name == "locate" and "not a stack template" in stop.summary
