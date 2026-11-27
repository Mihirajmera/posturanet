"""Destructive-change rules for the gate (FR-55): a plan that deletes data stops for a human.

Read-only, no contract needed. A Terraform plan that deletes or replaces a resource holding
data (a database, bucket, volume, file system, key, VPC, backup vault, audit log), or turns off
a guard that keeps data recoverable (deletion protection, the final snapshot, backups), is
BLOCK until a human lists the address in `contracts.allow_destroy` in `.posturanet.yml`. That
file is reviewed like code, and the agent hook tells agents not to edit it themselves.

`destructive_command` is the same idea for shell commands a coding agent is about to run
(`terraform destroy`, `apply -auto-approve`, `aws rds delete-db-instance` and similar).
"""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from posturanet.gate import ContractResult

CONFIG_FILE = ".posturanet.yml"

# Resources whose delete or replace loses data or something hard to rebuild. Sorted.
STATEFUL = frozenset(
    {
        "aws_backup_vault",
        "aws_cloudtrail",
        "aws_cloudwatch_log_group",
        "aws_db_cluster_snapshot",
        "aws_db_instance",
        "aws_db_snapshot",
        "aws_docdb_cluster",
        "aws_dynamodb_table",
        "aws_ebs_snapshot",
        "aws_ebs_volume",
        "aws_ecr_repository",
        "aws_efs_file_system",
        "aws_elasticache_cluster",
        "aws_elasticache_replication_group",
        "aws_elasticsearch_domain",
        "aws_fsx_lustre_file_system",
        "aws_fsx_ontap_file_system",
        "aws_fsx_windows_file_system",
        "aws_kinesis_stream",
        "aws_kms_key",
        "aws_memorydb_cluster",
        "aws_neptune_cluster",
        "aws_opensearch_domain",
        "aws_rds_cluster",
        "aws_redshift_cluster",
        "aws_route53_zone",
        "aws_s3_bucket",
        "aws_secretsmanager_secret",
        "aws_sqs_queue",
        "aws_vpc",
    }
)


def _turned_off(before: Any, after: Any) -> bool:
    return before is True and after is False


def _turned_on(before: Any, after: Any) -> bool:
    return before is not True and after is True


def _zeroed(before: Any, after: Any) -> bool:
    return isinstance(before, int) and before > 0 and after == 0


# attribute -> (test on before/after, what the change does)
GUARDS = {
    "deletion_protection": (_turned_off, "turns off deletion protection"),
    "deletion_protection_enabled": (_turned_off, "turns off deletion protection"),
    "skip_final_snapshot": (_turned_on, "skips the final snapshot on delete"),
    "force_destroy": (_turned_on, "allows deleting it with everything in it (force_destroy)"),
    "backup_retention_period": (_zeroed, "turns off automated backups"),
}


def _approved(address: str, allow: list[str]) -> bool:
    return any(fnmatchcase(address, pattern) for pattern in allow)


def judge_plan(changes: list[dict[str, Any]], allow: list[str]) -> list[ContractResult]:
    """One BLOCK result per resource the plan would destroy or leave unrecoverable."""
    from posturanet.gate import ContractResult, Violation

    results: list[ContractResult] = []
    for rc in sorted(changes, key=lambda r: str(r.get("address"))):
        address, kind = str(rc.get("address")), str(rc.get("type"))
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        before, after = change.get("before") or {}, change.get("after") or {}
        unknown = change.get("after_unknown") or {}
        problems: list[str] = []
        if "delete" in actions and kind in STATEFUL:
            verb = "replaces" if "create" in actions else "deletes"
            problems.append(f"the plan {verb} this {kind} (the data in it is lost)")
        if "update" in actions:
            for attr, (test, what) in GUARDS.items():
                if attr in after and not unknown.get(attr) and test(before.get(attr), after[attr]):
                    problems.append(f"the plan {what} ({attr})")
        if not problems or _approved(address, allow):
            continue
        result = ContractResult(address, CONFIG_FILE, "BLOCK", subject="change")
        result.violations = [Violation(p) for p in problems]
        result.reasons = problems
        result.rule = "destructive"
        result.fix = (
            f"if this is intended, a human adds {address!r} to contracts.allow_destroy "
            f"in {CONFIG_FILE} in the same PR"
        )
        results.append(result)
    return results


# Shell commands that destroy infrastructure or apply without a human looking at the plan.
_SEP = r"[^|;&\n]*"
_COMMANDS = [
    # `(?<!-)`: the `destroy` subcommand, not `plan -destroy`
    (rf"\b(terraform|tofu){_SEP}(?<!-)\bdestroy\b", "destroys every resource in the state"),
    (rf"\b(terraform|tofu){_SEP}\bapply\b{_SEP}-destroy\b", "destroys every resource in the state"),
    (
        rf"\b(terraform|tofu){_SEP}\bapply\b{_SEP}-auto-approve\b",
        "applies without a human reviewing the plan",
    ),
    (rf"\bpulumi{_SEP}(?<!-)\bdestroy\b", "destroys every resource in the stack"),
    (rf"\bcdk{_SEP}(?<!-)\bdestroy\b", "deletes the CloudFormation stacks"),
    (rf"\baws{_SEP}\bcloudformation\s+delete-stack\b", "deletes a CloudFormation stack"),
    (
        rf"\baws{_SEP}\b(rds\s+delete-db-(instance|cluster)|dynamodb\s+delete-table"
        r"|ec2\s+delete-volume|efs\s+delete-file-system|kms\s+schedule-key-deletion"
        r"|s3\s+rb|s3api\s+delete-bucket)\b",
        "deletes stored data",
    ),
    (rf"\baws{_SEP}\bs3\s+rm\b{_SEP}--recursive\b", "deletes every object under the prefix"),
]


def destructive_command(command: str) -> str | None:
    """What `command` would do, if it is one that destroys infrastructure or data."""
    for pattern, what in _COMMANDS:
        if re.search(pattern, command):
            return what
    return None
