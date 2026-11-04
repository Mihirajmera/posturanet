"""S3 public-access fixes: turn on all four Block Public Access settings (FR-50).

Bucket controls (S3.2, S3.3, S3.8) edit the bucket's `aws_s3_bucket_public_access_block`, or
add one next to the bucket when it has none. S3.1 does the same for the account-level
`aws_s3_account_public_access_block`. The fix ships only when the evidence shows nothing
uses public access (see `s3fix/evidence.py`).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from posturanet.configfix.catalog import Change, ConfigFix
from posturanet.configfix.hcl_attrs import Unsupported, apply_changes
from posturanet.errors import StageStop
from posturanet.locate import module_dir, resolve_block
from posturanet.locate.hcl_index import block_span, find_resource_block, offset_of_line
from posturanet.locate.tfstate import StateMatch, attributes_of, find_by_type
from posturanet.models import Config, Diff, FileChange, Location
from posturanet.synth.hcl_render import unified_diff

BUCKET_BPA = "aws_s3_bucket_public_access_block"
ACCOUNT_BPA = "aws_s3_account_public_access_block"
ACCOUNT_FILE = "s3_account_public_access_block.tf"
FLAG_NAMES = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)
FLAGS = [Change(path=n, op="set", value=True) for n in FLAG_NAMES]

# control -> scope. S3.19 (access points) is left out: its setting forces replacement.
CONTROLS: dict[str, Literal["bucket", "account"]] = {
    "S3.1": "account",
    "S3.2": "bucket",
    "S3.3": "bucket",
    "S3.8": "bucket",
}

_TITLES = {
    "S3.1": "S3 general purpose buckets should have block public access settings enabled",
    "S3.2": "S3 general purpose buckets should block public read access",
    "S3.3": "S3 general purpose buckets should block public write access",
    "S3.8": "S3 general purpose buckets should block public access",
}


def fix_for(control: str) -> ConfigFix:
    scope = CONTROLS[control]
    return ConfigFix(
        control=control,
        title=_TITLES[control],
        resource_type=ACCOUNT_BPA if scope == "account" else BUCKET_BPA,
        changes=FLAGS,
        scope="account" if scope == "account" else "resource",
        why="Block Public Access overrides public bucket policies and ACLs, now and later.",
        risk="medium",
    )


@dataclass
class S3Target:
    action: Literal["update", "create"]
    address: str  # the public access block's address
    file: str  # repo-relative
    line: int  # block header line (in the new text, for a create)
    bucket: str | None  # bucket name (bucket scope)


def _bpa_for_bucket(state: dict[str, Any], bucket: str) -> list[StateMatch]:
    return [
        m
        for m in find_by_type(state, BUCKET_BPA)
        if (attributes_of(state, m.address) or {}).get("bucket") == bucket
    ]


def _prefix(match: StateMatch) -> str:
    return f"{match.module}." if match.module else ""


def find_target(
    control: str,
    repo: Path,
    config: Config,
    state: dict[str, Any],
    bucket_loc: Location | None,
    bucket_match: StateMatch | None,
    bucket: str | None,
) -> S3Target:
    if CONTROLS[control] == "account":
        return _account_target(repo, config, state)
    assert bucket_loc is not None and bucket_match is not None and bucket is not None
    if "[" in bucket_loc.address:
        raise StageStop(
            "fix",
            f"{bucket_loc.address} uses count or for_each; PosturaNet won't edit every instance",
            ["add the public access block by hand for now"],
        )
    found = _bpa_for_bucket(state, bucket)
    if len(found) > 1:
        raise StageStop(
            "locate",
            f"{bucket} has {len(found)} public access blocks in state: "
            + ", ".join(m.address for m in found),
            ["remove the duplicate, then re-run"],
        )
    if found:
        _, line, file, _ = resolve_block(found[0], repo, config)
        return S3Target("update", found[0].address, _rel(file, repo), line, bucket)

    directory, _ = module_dir(bucket_match, repo, config)
    ref = re.compile(rf"\baws_s3_bucket\.{re.escape(bucket_match.name)}\b|\"{re.escape(bucket)}\"")
    for tf in sorted(directory.glob("*.tf")):
        text = tf.read_text(encoding="utf-8")
        for m in re.finditer(rf'resource\s+"{BUCKET_BPA}"\s+"([^"]+)"', text):
            i, j = block_span(text, m.start())
            if ref.search(text[i:j]):
                raise StageStop(
                    "fix",
                    f"{_rel(tf, repo)} already has {BUCKET_BPA}.{m.group(1)} for {bucket}, "
                    "but it's not in the state",
                    ["apply it through your pipeline first, then re-run"],
                )
    if find_resource_block(directory, BUCKET_BPA, bucket_match.name) is not None:
        raise StageStop(
            "fix",
            f"{BUCKET_BPA}.{bucket_match.name} already exists for another bucket",
            ["add the public access block by hand"],
        )
    address = f"{_prefix(bucket_match)}{BUCKET_BPA}.{bucket_match.name}"
    return S3Target("create", address, bucket_loc.file, bucket_loc.line, bucket)


def _account_target(repo: Path, config: Config, state: dict[str, Any]) -> S3Target:
    found = find_by_type(state, ACCOUNT_BPA)
    if len(found) > 1:
        raise StageStop(
            "locate",
            f"{len(found)} account public access blocks in state: "
            + ", ".join(m.address for m in found),
            ["keep one; the account setting is a single resource"],
        )
    if found:
        _, line, file, _ = resolve_block(found[0], repo, config)
        return S3Target("update", found[0].address, _rel(file, repo), line, None)
    root = (repo / config.terraform.root).resolve()
    for tf in sorted(root.rglob("*.tf")):
        if ACCOUNT_BPA in tf.read_text(encoding="utf-8"):
            raise StageStop(
                "fix",
                f"{_rel(tf, repo)} declares {ACCOUNT_BPA}, but it's not in this state",
                ["apply it first, or check you pointed at the right state"],
            )
    path = root / ACCOUNT_FILE
    return S3Target("create", f"{ACCOUNT_BPA}.this", _rel(path, repo), 1, None)


_BUCKET_BLOCK = """resource "aws_s3_bucket_public_access_block" "{name}" {{
  bucket = aws_s3_bucket.{name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
"""

_ACCOUNT_BLOCK = """# Added by PosturaNet (S3.1). Manage this account setting in one root only.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


def apply_fix(repo: Path, target: S3Target) -> tuple[Diff, S3Target, str | None, list[str]]:
    """(diff, target with the final line, original text or None for a new file, already set)."""
    path = repo / target.file
    if target.action == "update":
        original = path.read_bytes().decode("utf-8")
        try:
            edit = apply_changes(original, target.line, FLAGS)
        except Unsupported as exc:
            raise StageStop(
                "fix", str(exc), ["set the four Block Public Access flags by hand"]
            ) from exc
        if not edit.changed:
            raise StageStop(
                "fix",
                "the code already blocks public access, so the live resource has drifted",
                ["run terraform plan: it should show the fix pending; apply it in your pipeline"],
                why="PosturaNet fixes code, and this code is already fixed; the live "
                "resource isn't",
            )
        new, summary, already = edit.text, "; ".join(edit.changed), edit.already
    elif target.bucket is None:
        if path.exists():
            raise StageStop("fix", f"{target.file} already exists", ["add the block by hand"])
        original, new = None, _ACCOUNT_BLOCK
        summary, already = f"add {ACCOUNT_BPA}.this with all four settings on", []
    else:
        original = path.read_bytes().decode("utf-8")
        text = original.replace("\r\n", "\n")
        _, end = block_span(text, offset_of_line(text, target.line))
        name = target.address.rsplit(".", 1)[-1]
        block = _BUCKET_BLOCK.format(name=name)
        rest = text[end:].lstrip("\n")
        new = text[:end] + "\n\n" + block + ("\n" + rest if rest else "")
        line = text[:end].count("\n") + 3
        if "\r\n" in original:
            new = new.replace("\n", "\r\n")
        target = S3Target("create", target.address, target.file, line, target.bucket)
        summary, already = f"add {BUCKET_BPA}.{name} with all four settings on", []

    udiff = unified_diff(
        target.file, (original or "").replace("\r\n", "\n"), new.replace("\r\n", "\n")
    )
    diff = Diff(
        target_address=target.address,
        files=[FileChange(path=target.file, unified_diff=udiff, new_content=new)],
        summary=summary,
        generator="template:s3_public@1",
        sha256=hashlib.sha256(udiff.encode("utf-8")).hexdigest(),
    )
    return diff, target, original, already


def _rel(path: Path, repo: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


__all__ = ["CONTROLS", "FLAGS", "S3Target", "apply_fix", "find_target", "fix_for"]
