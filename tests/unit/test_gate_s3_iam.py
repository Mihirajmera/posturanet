"""check_change for S3 and IAM contracts: plan and source, BLOCK / UNKNOWN / PASS (FR-50, FR-51)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from posturanet.gate import check_plan, check_source
from posturanet.models.config import Config

OBSERVED = {
    "source": "test",
    "window": {"from": "2026-08-01", "to": "2026-10-30", "days": 90},
    "confidence": "high",
}
PARTNER = "arn:aws:iam::210987654321:role/partner"
CONFIG = Config()


def _repo(tmp_path: Path, tf: str, *contracts: tuple[str, dict[str, Any]]) -> Path:
    (tmp_path / "main.tf").write_text(tf, encoding="utf-8")
    directory = tmp_path / "posturanet" / "contracts"
    directory.mkdir(parents=True)
    for name, data in contracts:
        with (directory / name).open("w", encoding="utf-8") as fh:
            YAML(typ="safe").dump(data, fh)
    return tmp_path


def _iam(status: str = "approved") -> dict[str, Any]:
    return {
        "resource": "aws_iam_policy.app",
        "kind": "iam",
        "policy_arn": "arn:aws:iam::123456789012:policy/app",
        "observed": OBSERVED,
        "must_allow": [{"action": "ec2:DescribeInstances"}, {"action": "logs:CreateLogStream"}],
        "must_remove": ["ec2:*"],
        "status": status,
    }


def _s3(**extra: Any) -> dict[str, Any]:
    return {
        "resource": "aws_s3_bucket_public_access_block.assets",
        "kind": "s3_public",
        "observed": OBSERVED,
        "exposure": {
            "acme-assets": {
                "policy_public": False,
                "acl_public": False,
                "acls_enabled": False,
                "website": False,
            }
        },
        "status": "approved",
        **extra,
    }


def _partner_use() -> dict[str, Any]:
    return {
        "requester": PARTNER,
        "kind": "cross_account",
        "operations": ["REST.GET.OBJECT"],
        "count": 40,
        "last_seen": "2026-10-28",
        "owner": "partner-sftp",
    }


def _iam_tf(actions: list[str]) -> str:
    listed = ", ".join(f'"{a}"' for a in actions)
    return f"""resource "aws_iam_policy" "app" {{
  name = "app"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect   = "Allow"
        Action   = [{listed}]
        Resource = "*"
      }},
    ]
  }})
}}
"""


BLOCK_TF = """resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = %s
}
"""


def _policy_tf(statement: str) -> str:
    return (
        (BLOCK_TF % "true")
        + f"""
resource "aws_s3_bucket_policy" "assets" {{
  bucket = aws_s3_bucket.assets.id
  policy = jsonencode({{
    Version   = "2012-10-17"
    Statement = [{statement}]
  }})
}}
"""
    )


# --- IAM, source


def test_iam_source_passes_the_fixed_policy(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        _iam_tf(["ec2:DescribeInstances", "logs:CreateLogStream"]),
        ("iam.yaml", _iam()),
    )
    result = check_source(repo, CONFIG)
    assert result.status == "PASS", result.to_dict()
    assert result.results[0].source_file == "main.tf"


def test_iam_source_blocks_a_dropped_action_and_a_returned_wildcard(tmp_path: Path) -> None:
    repo = _repo(tmp_path, _iam_tf(["ec2:*"]), ("iam.yaml", _iam()))
    result = check_source(repo, CONFIG)
    assert result.status == "BLOCK"
    reasons = result.results[0].reasons
    assert "breaks must_allow: logs:CreateLogStream is no longer allowed" in reasons
    assert "breaks must_remove: ec2:* is allowed again" in reasons
    assert all(v.contract_line for v in result.results[0].violations)
    assert result.summary == "BLOCK · this change would break 1 contract"


def test_iam_draft_contract_is_labelled(tmp_path: Path) -> None:
    repo = _repo(tmp_path, _iam_tf(["ec2:DescribeInstances"]), ("iam.yaml", _iam("draft")))
    (reason,) = check_source(repo, CONFIG).results[0].reasons
    assert reason.endswith("(draft contract)")


def test_iam_source_non_literal_policy_is_unknown(tmp_path: Path) -> None:
    tf = 'resource "aws_iam_policy" "app" {\n  policy = data.aws_iam_policy_document.x.json\n}\n'
    repo = _repo(tmp_path, tf, ("iam.yaml", _iam()))
    assert check_source(repo, CONFIG).status == "UNKNOWN"


def test_iam_source_ignores_other_files(tmp_path: Path) -> None:
    repo = _repo(tmp_path, _iam_tf(["ec2:*"]), ("iam.yaml", _iam()))
    other = repo / "other.tf"
    other.write_text("", encoding="utf-8")
    assert check_source(repo, CONFIG, [other]).results == []


# --- IAM, plan


def _iam_plan(doc: dict[str, Any] | None, actions: list[str], unknown: bool = False) -> Any:
    return {
        "resource_changes": [
            {
                "address": "aws_iam_policy.app",
                "type": "aws_iam_policy",
                "mode": "managed",
                "change": {
                    "actions": actions,
                    "after": {"policy": json.dumps(doc)} if doc is not None else None,
                    "after_unknown": {"policy": True} if unknown else {},
                },
            }
        ]
    }


def _doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def test_iam_plan_pass_block_unknown_and_delete(tmp_path: Path) -> None:
    repo = _repo(tmp_path, _iam_tf(["ec2:*"]), ("iam.yaml", _iam()))
    good = _doc({"Effect": "Allow", "Action": ["ec2:DescribeInstances", "logs:*"], "Resource": "*"})
    assert check_plan(_iam_plan(good, ["update"]), repo, CONFIG).status == "PASS"

    denied = _doc(
        good["Statement"][0],
        {"Effect": "Deny", "Action": "logs:CreateLogStream", "Resource": "*"},
    )
    blocked = check_plan(_iam_plan(denied, ["update"]), repo, CONFIG)
    assert blocked.status == "BLOCK"
    assert blocked.results[0].reasons == ["breaks must_allow: logs:CreateLogStream is denied"]

    conditional = _doc(
        good["Statement"][0] | {"Condition": {"Bool": {"aws:SecureTransport": "true"}}}
    )
    assert check_plan(_iam_plan(conditional, ["update"]), repo, CONFIG).status == "UNKNOWN"
    assert check_plan(_iam_plan(None, ["update"], unknown=True), repo, CONFIG).status == "UNKNOWN"

    deleted = check_plan(_iam_plan(None, ["delete"]), repo, CONFIG)
    assert deleted.status == "BLOCK"
    assert deleted.results[0].caused_by == "planned policy in main.tf:1"


# --- S3, source


def test_s3_source_passes_all_four_flags(tmp_path: Path) -> None:
    repo = _repo(tmp_path, BLOCK_TF % "true", ("s3.yaml", _s3()))
    assert check_source(repo, CONFIG).status == "PASS"


def test_s3_source_blocks_a_flag_turned_off(tmp_path: Path) -> None:
    repo = _repo(tmp_path, BLOCK_TF % "false", ("s3.yaml", _s3()))
    result = check_source(repo, CONFIG)
    assert result.status == "BLOCK"
    assert result.results[0].reasons == [
        "breaks must_block: restrict_public_buckets is off, so public access can come back"
    ]


def test_s3_source_variable_flag_is_unknown(tmp_path: Path) -> None:
    repo = _repo(tmp_path, BLOCK_TF % "var.restrict", ("s3.yaml", _s3()))
    assert check_source(repo, CONFIG).status == "UNKNOWN"


def test_s3_source_blocks_a_public_policy(tmp_path: Path) -> None:
    public = '{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "*" }'
    repo = _repo(tmp_path, _policy_tf(public), ("s3.yaml", _s3()))
    result = check_source(repo, CONFIG)
    assert result.status == "BLOCK"
    assert "allows everyone (Principal *)" in result.results[0].reasons[0]


def test_s3_source_blocks_a_deny_on_a_kept_partner(tmp_path: Path) -> None:
    deny = f'{{ Effect = "Deny", Principal = {{ AWS = "{PARTNER}" }}, Action = "s3:*", Resource = "*" }}'  # noqa: E501
    allow = f'{{ Effect = "Allow", Principal = {{ AWS = "{PARTNER}" }}, Action = "s3:GetObject", Resource = "*" }}'  # noqa: E501
    contract = _s3(must_keep=[_partner_use()])
    repo = _repo(tmp_path, _policy_tf(f"{allow}, {deny}"), ("s3.yaml", contract))
    result = check_source(repo, CONFIG)
    assert result.status == "BLOCK"
    assert any(
        f"{PARTNER} (partner-sftp) is denied s3:GetObject" in r for r in result.results[0].reasons
    )  # noqa: E501


def test_s3_source_tls_only_deny_is_ignored(tmp_path: Path) -> None:
    allow = f'{{ Effect = "Allow", Principal = {{ AWS = "{PARTNER}" }}, Action = "s3:GetObject", Resource = "*" }}'  # noqa: E501
    tls = (
        '{ Effect = "Deny", Principal = "*", Action = "s3:*", Resource = "*", '
        'Condition = { Bool = { "aws:SecureTransport" = "false" } } }'
    )
    contract = _s3(must_keep=[_partner_use()])
    repo = _repo(tmp_path, _policy_tf(f"{allow}, {tls}"), ("s3.yaml", contract))
    assert check_source(repo, CONFIG).status == "PASS"


def test_s3_source_missing_partner_grant_is_unknown_not_block(tmp_path: Path) -> None:
    other = '{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::123456789012:root" }, Action = "s3:GetObject", Resource = "*" }'  # noqa: E501
    contract = _s3(must_keep=[_partner_use()])
    repo = _repo(tmp_path, _policy_tf(other), ("s3.yaml", contract))
    assert check_source(repo, CONFIG).status == "UNKNOWN"


# --- S3, plan


def _s3_plan(flags: dict[str, Any], policy_before: Any = None, policy_after: Any = None) -> Any:
    changes: list[dict[str, Any]] = [
        {
            "address": "aws_s3_bucket_public_access_block.assets",
            "type": "aws_s3_bucket_public_access_block",
            "mode": "managed",
            "change": {"actions": ["update"], "after": flags, "after_unknown": {}},
        }
    ]
    if policy_before is not None or policy_after is not None:
        changes.append(
            {
                "address": "aws_s3_bucket_policy.assets",
                "type": "aws_s3_bucket_policy",
                "mode": "managed",
                "change": {
                    "actions": ["update"],
                    "before": {"bucket": "acme-assets", "policy": json.dumps(policy_before)},
                    "after": {"bucket": "acme-assets", "policy": json.dumps(policy_after)},
                    "after_unknown": {},
                },
            }
        )
    return {"resource_changes": changes}


ON = dict.fromkeys(
    ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"],
    True,
)


def test_s3_plan_flags(tmp_path: Path) -> None:
    repo = _repo(tmp_path, BLOCK_TF % "true", ("s3.yaml", _s3()))
    assert check_plan(_s3_plan(ON), repo, CONFIG).status == "PASS"
    assert check_plan(_s3_plan(ON | {"block_public_acls": False}), repo, CONFIG).status == "BLOCK"


def test_s3_plan_blocks_a_removed_partner_grant(tmp_path: Path) -> None:
    repo = _repo(tmp_path, BLOCK_TF % "true", ("s3.yaml", _s3(must_keep=[_partner_use()])))
    grant = {
        "Effect": "Allow",
        "Principal": {"AWS": PARTNER},
        "Action": "s3:GetObject",
        "Resource": "*",
    }  # noqa: E501
    other = {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
        "Action": "s3:*",
        "Resource": "*",
    }  # noqa: E501
    kept = check_plan(_s3_plan(ON, _doc(grant), _doc(grant, other)), repo, CONFIG)
    assert kept.status == "PASS", kept.to_dict()
    lost = check_plan(_s3_plan(ON, _doc(grant), _doc(other)), repo, CONFIG)
    assert lost.status == "BLOCK"
    assert any("loses its grant on acme-assets" in r for r in lost.results[0].reasons)


def test_mixed_contract_kinds_load_together(tmp_path: Path) -> None:
    tf = _iam_tf(["ec2:DescribeInstances", "logs:CreateLogStream"]) + "\n" + BLOCK_TF % "true"
    repo = _repo(tmp_path, tf, ("iam.yaml", _iam()), ("s3.yaml", _s3()))
    result = check_source(repo, CONFIG)
    assert result.status == "PASS"
    assert result.summary == "PASS · 2 contracts checked"
