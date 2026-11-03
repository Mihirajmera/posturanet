from __future__ import annotations

import json
from pathlib import Path

import pytest

from posturanet.errors import StageStop, UsageError
from posturanet.ingest import ingest
from posturanet.ingest.asff import parse_asff
from posturanet.models import FixType, Severity


def test_asff_file_normalizes(sg_finding_path: Path) -> None:
    f = ingest(str(sg_finding_path))
    assert f.control_id == "EC2.19"
    assert f.fix_type is FixType.SG_INGRESS
    assert f.severity is Severity.HIGH
    assert f.resource.id == "sg-0a91f3c2"
    assert f.resource.account == "123456789012"
    assert f.resource.region == "us-east-1"
    assert f.provenance.schema_name == "asff-2018-10-08"
    assert len(f.provenance.raw_sha256) == 64


def test_finding_text_is_kept_as_data(sg_finding_path: Path) -> None:
    f = ingest(str(sg_finding_path))
    assert "Security groups" in f.title


def _base(**overrides: object) -> dict[str, object]:
    item: dict[str, object] = {
        "Id": "x",
        "Severity": {"Label": "LOW"},
        "Resources": [{"Type": "AwsEc2SecurityGroup", "Id": "arn:aws:ec2:r:1:security-group/sg-1"}],
    }
    item.update(overrides)
    return item


def test_control_id_from_generator() -> None:
    f = parse_asff(_base(GeneratorId="aws-foundational/v/1.0.0/EC2.18"), raw_sha256="0" * 64)
    assert f.control_id == "EC2.18"
    assert f.resource.id == "sg-1"


def test_unknown_control_is_unsupported() -> None:
    f = parse_asff(_base(), raw_sha256="0" * 64)
    assert f.fix_type is FixType.UNSUPPORTED


def test_missing_fields_stop() -> None:
    with pytest.raises(StageStop, match="Resources"):
        parse_asff({"Id": "x", "Severity": {}}, raw_sha256="0" * 64)


def test_multiple_findings_rejected() -> None:
    with pytest.raises(UsageError, match="exactly 1"):
        parse_asff({"Findings": [_base(), _base()]}, raw_sha256="0" * 64)


def test_invalid_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(UsageError, match="not valid JSON"):
        ingest(str(p))


def test_manual_resource_id() -> None:
    f = ingest("sg-0a91f3c2")
    assert f.fix_type is FixType.SG_INGRESS
    assert f.finding_id == "manual:sg-0a91f3c2"


def test_manual_unknown_prefix() -> None:
    with pytest.raises(UsageError):
        ingest("vpc-123")


def test_bare_list_document(tmp_path: Path) -> None:
    p = tmp_path / "one.json"
    p.write_text(json.dumps([_base()]), encoding="utf-8")
    assert ingest(str(p)).finding_id == "x"
