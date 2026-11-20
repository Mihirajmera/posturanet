"""Wiz, Orca and Prisma Cloud exports (FR-4d): mapped from the export or the customer, never
guessed; unmapped rules still end in an outcome."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from posturanet.cli.app import app
from posturanet.errors import StageStop, UsageError
from posturanet.ingest import ingest, issue_of, read_findings, vendors
from posturanet.models import FixType
from posturanet.models.config import load_config
from posturanet.outcomes import outcome

FIND = Path(__file__).resolve().parents[1] / "fixtures" / "findings"
WIZ, ORCA, PRISMA = FIND / "wiz_issues.json", FIND / "orca_alerts.json", FIND / "prisma_alerts.json"
HUB = FIND / "sg_ssh_open.json"
ORCA_RULES = {"orca": {"S3 bucket allows public access": "S3.8"}}
TODAY = date(2026, 11, 17)
runner = CliRunner()


def _outcomes(path: Path, rules: vendors.Rules | None = None) -> list[str]:
    return [outcome(e, [], TODAY)[0] for e in read_findings(path, rules).entries]


@pytest.mark.parametrize(("path", "fmt"), [(WIZ, "wiz"), (ORCA, "orca"), (PRISMA, "prisma")])
def test_each_export_is_detected(path: Path, fmt: str) -> None:
    found = read_findings(path)
    assert found.format == fmt and len(found.entries) == 3
    assert found.entries[2].reason is not None and "nothing to fix" in found.entries[2].reason


def test_control_comes_from_the_export() -> None:
    for path in (WIZ, PRISMA):
        e = read_findings(path).entries[0]
        assert e.fixable and e.finding is not None
        assert e.finding.control_id == "EC2.19"  # the FSBP id; CIS "5.2" isn't a control id
        assert e.finding.fix_type is FixType.SG_INGRESS
        assert e.finding.resource.id == "sg-0a91f3c2"
        assert e.finding.resource.account == "123456789012"
        assert e.finding.resource.region == "us-east-1"
    assert _outcomes(WIZ) == ["fix", "none", "passed"]
    assert _outcomes(PRISMA) == ["fix", "none", "passed"]


def test_unmapped_rule_has_a_stated_reason() -> None:
    e = read_findings(WIZ).entries[1]
    assert not e.fixable and e.finding is not None
    assert e.reason == (
        "Wiz rule 00000000-0000-4000-8000-0000000000r2 has no control mapping; "
        "add it under detectors.wiz.rules"
    )
    orca = read_findings(ORCA).entries[0]  # Orca exports carry no control ids
    assert orca.reason is not None and "detectors.orca.rules" in orca.reason
    assert _outcomes(ORCA) == ["none", "none", "passed"]


def test_customer_mapping() -> None:
    e = read_findings(ORCA, ORCA_RULES).entries[0]
    assert e.fixable and e.finding is not None and e.finding.control_id == "S3.8"
    assert e.finding.resource.id == "acme-reports" and e.finding.resource.account == "123456789012"
    assert _outcomes(ORCA, ORCA_RULES) == ["fix", "none", "passed"]
    # the customer's mapping wins over the export
    rules = {"prisma": {"00000000-0000-4000-8000-0000000000p1": "EC2.13"}}
    assert read_findings(PRISMA, rules).entries[0].control_id == "EC2.13"


def test_export_naming_several_controls_stops() -> None:
    doc = json.loads(PRISMA.read_text(encoding="utf-8"))
    alert = copy.deepcopy(doc["items"][0])
    alert["policy"]["complianceMetadata"].append(
        {"standardName": "AWS Foundational Security Best Practices", "sectionId": "S3.8"}
    )
    with pytest.raises(StageStop, match="several controls"):
        vendors.parse_item(alert, "prisma", raw_sha256="0" * 64)


def test_merges_with_other_scanners() -> None:
    keys = {issue_of(read_findings(p).entries[0].finding) for p in (HUB, WIZ, PRISMA)}  # type: ignore[arg-type]
    assert keys == {("sg_ingress", "123456789012", "sg-0a91f3c2")}
    args = ["findings", "list", str(HUB), str(WIZ), str(PRISMA), "--all", "--format", "json"]
    rows = json.loads(runner.invoke(app, args).output)
    sg = [r for r in rows if r["resource"] == "sg-0a91f3c2"]
    assert len(sg) == 1 and sg[0]["also"] == "also prisma, wiz"


def test_list_shows_reason_and_counts_coverage() -> None:
    text = runner.invoke(app, ["findings", "list", str(WIZ), "--all"]).output
    assert "WIZ · 2 failed · 1 fix" in text and "coverage 1/2 (50%)" in text
    assert "has no control mapping; add it under detectors.wiz.rules" in text


def test_list_reads_mappings_from_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".posturanet.yml").write_text(
        "version: 1\ndetectors:\n  orca:\n    rules:\n      S3 bucket allows public access: S3.8\n",
        encoding="utf-8",
    )
    assert load_config(tmp_path)[0].detectors.rules()["orca"] == ORCA_RULES["orca"]
    monkeypatch.chdir(tmp_path)
    rows = json.loads(
        runner.invoke(app, ["findings", "list", str(ORCA), "--all", "--format", "json"]).output
    )
    assert [r["outcome"] for r in rows] == ["fix", "none", "passed"]


def test_split_then_fix(tmp_path: Path) -> None:
    out = tmp_path / "split"
    result = runner.invoke(app, ["findings", "split", str(WIZ), "--out", str(out)])
    assert result.exit_code == 0, result.output
    (one,) = out.iterdir()
    assert read_findings(one).format == "wiz"
    assert ingest(str(one)).control_id == "EC2.19"


def test_fix_on_an_unmapped_alert_stops(tmp_path: Path) -> None:
    doc = json.loads(WIZ.read_text(encoding="utf-8"))
    alone = tmp_path / "one.json"
    alone.write_text(
        json.dumps(vendors.document_for(doc["data"]["issues"]["nodes"][1], "wiz")),
        encoding="utf-8",
    )
    with pytest.raises(StageStop, match="no control mapping"):
        ingest(str(alone))


def test_csv_is_refused_not_guessed(tmp_path: Path) -> None:
    csv = tmp_path / "issues.csv"
    csv.write_text("Issue ID,Rule,Resource\n1,r,sg-0a91f3c2\n", encoding="utf-8")
    with pytest.raises(UsageError, match="CSV") as err:
        read_findings(csv)
    # The refusal says how to get the same findings in a form PosturaNet reads.
    msg = str(err.value)
    assert "issuesV2" in msg and "/api/serving-layer/query" in msg and "/v2/alert" in msg
    assert msg.endswith("docs/vendor-exports.md")
    assert (Path(__file__).parents[2] / "docs" / "vendor-exports.md").is_file()


def test_unknown_detector_key_is_an_error(tmp_path: Path) -> None:
    (tmp_path / ".posturanet.yml").write_text(
        "version: 1\ndetectors:\n  wizz: {}\n", encoding="utf-8"
    )
    with pytest.raises(UsageError, match="wizz"):
        load_config(tmp_path)
