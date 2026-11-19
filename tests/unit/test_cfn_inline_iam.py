"""CloudFormation inline IAM policies: Role/User/Group `Policies`, `AWS::IAM::Policy`, SAM
function `Policies` (FR-10a, FR-51)."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from posturanet.cfn.template import parse, value
from posturanet.evidence import FileSource
from posturanet.gate import check_source
from posturanet.iamfix.evidence import LiveIamSource
from posturanet.models.config import load_config
from posturanet.pipeline import Context, run_fix, run_fix_full

FIX = Path(__file__).resolve().parents[1] / "fixtures"
CFN = FIX / "cfn" / "inline_iam"
NOW = datetime(2026, 10, 30, tzinfo=UTC)
USED = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "logs:CreateLogStream"]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    dst = tmp_path / "repo"
    shutil.copytree(CFN, dst)
    return dst


def _finding(tmp: Path, arn: str, rtype: str = "AwsIamRole") -> str:
    raw = json.loads((FIX / "findings/iam21_app.json").read_text("utf-8"))
    raw["Findings"][0]["Resources"] = [{"Type": rtype, "Id": arn, "Region": "us-east-1"}]
    path = tmp / f"finding-{arn.rsplit('/', 1)[-1]}.json"
    path.write_text(json.dumps(raw), "utf-8")
    return str(path)


def _evidence(tmp: Path, arn: str) -> Path:
    raw = json.loads((FIX / "iam/app.json").read_text("utf-8"))
    raw["policy_arn"] = arn
    raw["principals"] = [arn.split(":", 5)[-1]]
    path = tmp / f"evidence-{arn.rsplit('/', 1)[-1]}.json"
    path.write_text(json.dumps(raw), "utf-8")
    return path


def _run(repo: Path, arn: str, rtype: str = "AwsIamRole", **kw: Any) -> Any:
    tmp = repo.parent
    ctx = Context(evidence=FileSource(_evidence(tmp, arn)), clock=lambda: NOW, **kw)
    return run_fix_full(_finding(tmp, arn, rtype), repo, load_config(repo)[0], ctx)


def _arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::123456789012:{kind}/{name}"


def test_role_inline_policy_picks_the_wildcard_entry(repo: Path) -> None:
    record, _ = _run(repo, _arn("role", "apps-WorkerRole-EXAMPLE"))
    assert record.result == "DRY RUN", record.stages
    assert record.location.address == "cfn.apps.WorkerRole.worker-data"
    assert record.diff.target_address == "cfn.apps.WorkerRole.worker-data"
    udiff = record.diff.files[0].unified_diff
    assert "-                  - ec2:*\n" in udiff
    assert "+                  - ec2:DescribeInstances\n" in udiff
    assert "logs:PutLogEvents" not in udiff  # worker-logs untouched
    new = record.diff.files[0].new_content
    assert "- Sid: Data  # keep this comment" in new
    policies = value(parse(new, repo / "t.yaml").resources["WorkerRole"])["Properties"]["Policies"]
    assert policies[0]["PolicyDocument"]["Statement"][0]["Action"] == "logs:PutLogEvents"
    assert policies[1]["PolicyDocument"]["Statement"][0]["Action"] == USED


def test_user_with_standalone_policy_resource(repo: Path) -> None:
    record, _ = _run(repo, _arn("user", "apps-ReportsUser-EXAMPLE"), "AwsIamUser")
    assert record.result == "DRY RUN", record.stages
    assert record.location.address == "cfn.apps.ReportsPolicy"
    new = record.diff.files[0].new_content
    stmt = value(parse(new, repo / "t.yaml").resources["ReportsPolicy"])["Properties"]
    assert stmt["PolicyDocument"]["Statement"][0]["Action"] == USED
    assert '            Action: ["ec2:DescribeInstances", ' in new  # flow list stays flow


def test_group_policy_json_keeps_layout(repo: Path) -> None:
    record, _ = _run(repo, _arn("group", "ops-OpsGroup-EXAMPLE"), "AwsIamGroup")
    assert record.result == "DRY RUN", record.stages
    assert record.location.address == "cfn.ops.OpsPolicy"
    udiff = record.diff.files[0].unified_diff
    assert '+                "ec2:DescribeInstances",\n' in udiff
    doc = json.loads(record.diff.files[0].new_content)["Resources"]["OpsPolicy"]["Properties"]
    assert doc["PolicyDocument"]["Statement"][0]["Action"] == USED


def test_sam_function_statement_document(repo: Path) -> None:
    record, _ = _run(repo, _arn("role", "sam-IngestFunctionRole-EXAMPLE"))
    assert record.result == "DRY RUN", record.stages
    assert record.location.address == "cfn.sam.IngestFunction.IngestFunctionRolePolicy1"
    assert any("role SAM generates for IngestFunction" in r for r in record.location.reasoning)
    new = record.diff.files[0].new_content
    pols = value(parse(new, repo / "t.yaml").resources["IngestFunction"])["Properties"]["Policies"]
    assert pols[0] == "AWSLambdaBasicExecutionRole"
    assert pols[1]["Statement"][0]["Action"] == USED


@pytest.mark.parametrize(
    ("arn", "why"),
    [
        (_arn("role", "sam-ThumbsFunctionRole-EXAMPLE"), "SAM policy template S3ReadPolicy"),
        (_arn("role", "apps-BatchRole-EXAMPLE"), "2 policies on BatchRole"),
        (_arn("role", "apps-UploadRole-EXAMPLE"), "Resource is not a literal value"),
    ],
)
def test_unmappable_inline_policies_stop_unknown(repo: Path, arn: str, why: str) -> None:
    record, proposal = _run(repo, arn)
    assert proposal is None
    assert record.result == "STOPPED" and record.exit_code == 3, record.stages
    assert any(why in s.summary for s in record.stages), [s.summary for s in record.stages]


def _fake_aws(body: str) -> Any:
    from posturanet.aws.readonly import ReadOnlyClient

    class Cfn:
        def get_template(self, **kw: Any) -> dict[str, Any]:
            return {"TemplateBody": body}

    return lambda service: ReadOnlyClient(Cfn(), service)


def test_contract_check_source_inline_policy(repo: Path) -> None:
    config, _ = load_config(repo)
    arn = _arn("role", "apps-WorkerRole-EXAMPLE")
    template = repo / "templates/apps.yaml"
    ctx = Context(
        evidence=FileSource(_evidence(repo.parent, arn)),
        clock=lambda: NOW,
        mode="check",
        aws=_fake_aws(template.read_text("utf-8")),
    )
    record = run_fix(_finding(repo.parent, arn), repo, config, ctx)
    assert record.result == "VALIDATED", record.stages
    assert (repo / "posturanet/contracts/cfn.apps.WorkerRole.worker-data.yaml").is_file()
    assert check_source(repo, config, [template]).status != "PASS"  # wildcard still there
    template.write_text(record.diff.files[0].new_content, "utf-8")
    result = check_source(repo, config, [template])
    assert result.status == "PASS", result.results


def test_live_evidence_for_a_role_reads_the_role() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    class Iam:
        def get_role(self, **kw: Any) -> dict[str, Any]:
            calls.append(("get_role", kw))
            return {"Role": {"CreateDate": "2025-06-01T00:00:00Z"}}

        def generate_service_last_accessed_details(self, **kw: Any) -> dict[str, Any]:
            calls.append(("generate", kw))
            return {"JobId": "j"}

        def get_service_last_accessed_details(self, **kw: Any) -> dict[str, Any]:
            return {"JobStatus": "COMPLETED", "ServicesLastAccessed": []}

    arn = "arn:aws:iam::123456789012:role/svc/apps-WorkerRole-EXAMPLE"
    ev = LiveIamSource(Iam(), sleep=lambda _: None).policy(arn, date(2026, 10, 30))
    assert ev.principals == ["role/apps-WorkerRole-EXAMPLE"]
    assert calls[0] == ("get_role", {"RoleName": "apps-WorkerRole-EXAMPLE"})
    assert calls[1] == ("generate", {"Arn": arn, "Granularity": "ACTION_LEVEL"})
