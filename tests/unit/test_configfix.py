from __future__ import annotations

import pytest

from posturanet.configfix.catalog import Change, ConfigFix, catalog, controls, fixes_for
from posturanet.configfix.hcl_attrs import (
    ABSENT,
    Unsupported,
    applies,
    apply_changes,
    lookup,
    parse_literal,
    satisfied,
)
from posturanet.configfix.validate import plan_matches
from posturanet.ingest.controls import fix_type_for
from posturanet.models import CheckResult, FixType
from tests_support import config_fixture as _fixture_for

DB = """\
resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  skip_final_snapshot = true
}
"""


def _set(path: str, value: object) -> Change:
    return Change(path=path, op="set", value=value)  # type: ignore[arg-type]


# --- catalog


def test_catalog_has_at_least_50_fixes_and_is_consistent() -> None:
    rows = catalog()
    assert len(rows) >= 50
    assert len(controls()) >= 50
    seen = set()
    for f in rows:
        assert f.resource_type.startswith("aws_"), f.control
        assert f.changes, f.control
        assert (f.control, f.resource_type) not in seen, f.control
        seen.add((f.control, f.resource_type))
        # A control's rows share one scope, so locate knows how to match the resource.
        assert {r.scope for r in fixes_for(f.control)} == {f.scope}


def test_catalog_never_overlaps_evidence_fixes() -> None:
    for control in controls():
        assert fix_type_for(control) is FixType.CONFIG_ATTRIBUTE, control
    assert fix_type_for("EC2.19") is FixType.SG_INGRESS
    assert fix_type_for("Nope.1") is FixType.UNSUPPORTED


def test_catalog_text_is_honest() -> None:
    for f in catalog():
        text = f"{f.title} {f.why} {f.note or ''}".lower()
        for word in ("guarantee", "proven safe", "100%", "zero risk", "postura "):
            assert word not in text, (f.control, word)


@pytest.mark.parametrize("fix", catalog(), ids=lambda f: f"{f.control}:{f.resource_type}")
def test_every_fix_round_trips(fix: ConfigFix) -> None:
    text = _fixture_for(fix)
    ok, why = applies(text, 1, fix.when)
    assert ok, why

    edit = apply_changes(text, 1, fix.changes)
    assert edit.changed
    assert all(satisfied(edit.text, 1, c) for c in fix.changes)
    # Already fixed: a second run changes nothing (no churn PRs).
    again = apply_changes(edit.text, 1, fix.changes)
    assert again.changed == [] and again.text == edit.text


@pytest.mark.parametrize("fix", catalog(), ids=lambda f: f"{f.control}:{f.resource_type}")
def test_every_fix_replaces_a_wrong_value_in_place(fix: ConfigFix) -> None:
    text = _fixture_for(fix)
    wrong = []
    for c in fix.changes:
        if c.op == "set" and isinstance(c.value, bool):
            wrong.append(_set(c.path, not c.value))
        elif c.op == "at_least":
            wrong.append(_set(c.path, 0))
        elif c.op == "includes":
            wrong.append(_set(c.path, ["other"]))
    if not wrong:
        pytest.skip("no wrong value to seed")
    seeded = apply_changes(text, 1, wrong).text
    edit = apply_changes(seeded, 1, fix.changes)
    assert all(satisfied(edit.text, 1, c) for c in fix.changes)
    assert edit.text.count("\n") == seeded.count("\n") + _inserted_lines(fix, wrong)


def _inserted_lines(fix: ConfigFix, seeded: list[Change]) -> int:
    paths = {c.path for c in seeded}
    missing = [c for c in fix.changes if c.path not in paths]
    return len(missing) + 1 if missing else 0  # a blank line, then the group


# --- literals and lookup


@pytest.mark.parametrize(
    ("src", "value"),
    [
        ("true", True),
        ("7", 7),
        ('"SSE_S3"', "SSE_S3"),
        ('["audit", "error"]', ["audit", "error"]),
        ('["a",\n  "b",\n]', ["a", "b"]),
        ("null", None),
    ],
)
def test_literals(src: str, value: object) -> None:
    assert parse_literal(src) == value


def test_non_literals_are_refused() -> None:
    text = DB.replace('"postgres"', "var.engine")
    with pytest.raises(Unsupported, match="not a literal"):
        lookup(text, 1, "engine")
    with pytest.raises(Unsupported, match="expression"):
        apply_changes(text.replace("skip_final", "deletion_protection = var.dp\n  skip_final"), 1,
                      [_set("deletion_protection", True)])  # fmt: skip
    template = DB.replace('"orders"', '"${var.env}-orders"', 1)
    with pytest.raises(Unsupported):
        lookup(template, 1, "identifier")


def test_lookup_absent_and_nested() -> None:
    assert lookup(DB, 1, "multi_az") is ABSENT
    assert lookup(DB, 1, "engine") == "postgres"
    text = apply_changes(DB, 1, [_set("point_in_time_recovery.enabled", True)]).text
    assert lookup(text, 1, "point_in_time_recovery.enabled") is True


def test_when_conditions() -> None:
    rds36 = next(f for f in fixes_for("RDS.36"))
    assert applies(DB, 1, rds36.when) == (True, "")
    mysql = DB.replace('"postgres"', '"mysql"')
    ok, why = applies(mysql, 1, rds36.when)
    assert not ok and 'engine is "mysql"' in why


# --- editing


def test_insert_keeps_fmt_alignment_with_its_own_group() -> None:
    out = apply_changes(DB, 1, [_set("deletion_protection", True), _set("multi_az", True)]).text
    assert out == DB.replace(
        "skip_final_snapshot = true\n",
        "skip_final_snapshot = true\n\n  deletion_protection = true\n  multi_az            = true\n",
    )


def test_replace_keeps_the_rest_of_the_line() -> None:
    text = DB.replace("skip_final_snapshot = true", "skip_final_snapshot = false # keep")
    out = apply_changes(text, 1, [_set("skip_final_snapshot", True)]).text
    assert "skip_final_snapshot = true # keep" in out


def test_at_least_never_lowers() -> None:
    text = 'resource "aws_docdb_cluster" "x" {\n  backup_retention_period = 30\n}\n'
    change = Change(path="backup_retention_period", op="at_least", value=7)
    assert apply_changes(text, 1, [change]).changed == []
    quoted = text.replace("30", '"30"')
    assert apply_changes(quoted, 1, [change]).changed == []


def test_includes_appends_only_missing() -> None:
    text = 'resource "aws_eks_cluster" "x" {\n  enabled_cluster_log_types = ["api"]\n}\n'
    change = Change(path="enabled_cluster_log_types", op="includes", value=["audit"])
    out = apply_changes(text, 1, [change]).text
    assert 'enabled_cluster_log_types = ["api", "audit"]' in out


def test_nested_block_created_inside_existing_parent() -> None:
    text = (
        'resource "aws_athena_workgroup" "x" {\n'
        '  name = "x"\n\n'
        "  configuration {\n"
        "    enforce_workgroup_configuration = true\n"
        "  }\n"
        "}\n"
    )
    path = "configuration.result_configuration.encryption_configuration.encryption_option"
    out = apply_changes(text, 1, [_set(path, "SSE_S3")]).text
    assert out == text.replace(
        "    enforce_workgroup_configuration = true\n",
        "    enforce_workgroup_configuration = true\n\n"
        "    result_configuration {\n"
        "      encryption_configuration {\n"
        '        encryption_option = "SSE_S3"\n'
        "      }\n"
        "    }\n",
    )


def test_empty_block_and_crlf() -> None:
    text = 'resource "aws_ebs_encryption_by_default" "this" {}\r\n'
    out = apply_changes(text, 1, [_set("enabled", True)]).text
    assert out == 'resource "aws_ebs_encryption_by_default" "this" {\r\n  enabled = true\r\n}\r\n'


def test_second_resource_in_file_and_braces_in_strings() -> None:
    text = 'resource "aws_kms_key" "a" {\n  description = "a {b} c # d"\n}\n\n' + DB
    out = apply_changes(text, 5, [_set("deletion_protection", True)]).text
    assert out.startswith('resource "aws_kms_key" "a" {\n  description = "a {b} c # d"\n}\n')
    assert "deletion_protection = true" in out.split("aws_db_instance", 1)[1]


@pytest.mark.parametrize(
    ("body", "match"),
    [
        (
            '  dynamic "point_in_time_recovery" {\n    for_each = [1]\n    content {}\n  }\n',
            "dynamic",
        ),
        ("  point_in_time_recovery = { enabled = false }\n", "object syntax"),
        ("  point_in_time_recovery {}\n  point_in_time_recovery {}\n", "2"),
        ("  lifecycle {\n    ignore_changes = [point_in_time_recovery]\n  }\n", "ignore_changes"),
        ("  lifecycle {\n    ignore_changes = all\n  }\n", "ignore_changes"),
        ("  policy = <<EOT\n{}\nEOT\n", "heredoc"),
    ],
)
def test_fails_closed(body: str, match: str) -> None:
    text = f'resource "aws_dynamodb_table" "t" {{\n  name = "t"\n{body}}}\n'
    with pytest.raises(Unsupported, match=match):
        apply_changes(text, 1, [_set("point_in_time_recovery.enabled", True)])


def test_closing_brace_sharing_a_line_is_refused() -> None:
    text = 'resource "aws_kms_key" "a" {\n  description = "a" }\n'
    with pytest.raises(Unsupported, match="shares a line"):
        apply_changes(text, 1, [_set("enable_key_rotation", True)])


# --- plan check


def _rc(before: dict[str, object], after: dict[str, object]) -> dict[str, object]:
    return {"address": "x", "change": {"actions": ["update"], "before": before, "after": after}}


def test_plan_matches() -> None:
    fix = fixes_for("DynamoDB.2")[0]
    good = _rc({"name": "t"}, {"name": "t", "point_in_time_recovery": [{"enabled": True}]})
    assert plan_matches(good, fix).result is CheckResult.PASS

    off = _rc({}, {"point_in_time_recovery": [{"enabled": False}]})
    assert plan_matches(off, fix).result is CheckResult.FAIL

    drift = _rc(
        {"billing_mode": "PROVISIONED"},
        {"billing_mode": "PAY_PER_REQUEST", "point_in_time_recovery": [{"enabled": True}]},
    )
    check = plan_matches(drift, fix)
    assert check.result is CheckResult.FAIL and "billing_mode" in check.detail

    tags = _rc({"tags_all": {}}, {"tags_all": {"a": "b"}, "point_in_time_recovery": [{"enabled": True}]})  # fmt: skip
    assert plan_matches(tags, fix).result is CheckResult.PASS

    unknown = _rc({}, {})
    unknown["change"]["after_unknown"] = {"point_in_time_recovery": [{"enabled": True}]}  # type: ignore[index]
    assert plan_matches(unknown, fix).result is CheckResult.ERROR
    assert plan_matches(None, fix).result is CheckResult.FAIL
