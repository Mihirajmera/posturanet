"""Locate stage: resource id -> state address -> file:line -> owners (FR-5..FR-10).

Never guesses. Anything ambiguous or outside the supported layout stops the run (NFR-1).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from posturanet.errors import StageStop
from posturanet.locate.backend import S3Fetch, find_s3_backend
from posturanet.locate.codeowners import find_codeowners, owners_for
from posturanet.locate.hcl_index import find_module_source, find_resource_block, is_local_source
from posturanet.locate.tfstate import (
    StateMatch,
    find_by_type,
    find_resource,
    load_state,
    parse_state,
)
from posturanet.models import Confidence, Config, Finding, Location


def locate(
    finding: Finding,
    repo: Path,
    config: Config,
    state_path: Path | None = None,
    s3_fetch: S3Fetch | None = None,
) -> Location:
    return locate_match(finding, repo, config, state_path, s3_fetch)[0]


def locate_match(
    finding: Finding,
    repo: Path,
    config: Config,
    state_path: Path | None = None,
    s3_fetch: S3Fetch | None = None,
    *,
    resource_types: Sequence[str] = (),
    account_scope: bool = False,
) -> tuple[Location, StateMatch]:
    """`resource_types` narrows the match, first type preferred. With `account_scope`, the
    finding names the account, so the match is the one resource of that type in state."""
    tf_root = (repo / config.terraform.root).resolve()
    state, state_label = _load_state(repo, tf_root, config, state_path, s3_fetch)

    if account_scope:
        matches, how = _by_type(state, resource_types), "type matched in state"
        if not matches:
            raise StageStop(
                "locate",
                f"no {' or '.join(resource_types)} in the Terraform state",
                [
                    "this fix edits an existing resource; adding a new one is not an attribute fix",
                    "add the resource by hand, or check you pointed at the right state",
                ],
            )
    else:
        matches = find_resource(state, finding.resource.id, finding.resource.arn)
        how = "id matched in state"
        if resource_types:
            matches = _prefer(matches, resource_types)
            if not matches:
                raise StageStop(
                    "locate",
                    f"{finding.resource.id} is not in the Terraform state as "
                    + " or ".join(resource_types),
                    [
                        "check that this resource is managed by Terraform in this repo",
                        "if it was created in the console, codifying it comes in a later release",
                    ],
                )
    if not matches:
        raise StageStop(
            "locate",
            f"{finding.resource.id} is not in the Terraform state",
            [
                "check that this resource is managed by Terraform in this repo",
                "if it was created in the console, codifying it comes in a later release",
            ],
        )
    if len(matches) > 1:
        raise StageStop(
            "locate",
            f"{finding.resource.id} matches {len(matches)} state entries: "
            + ", ".join(m.address for m in matches),
            ["tell PosturaNet which address owns it (coming in R1), or fix the duplicate state"],
        )
    match = matches[0]
    reasoning = [f"{how} {state_label}"]

    directory = tf_root
    for name in match.module_names:
        found = find_module_source(directory, name)
        if found is None:
            raise StageStop(
                "locate", f'module "{name}" block not found in {_rel(directory, repo)}/'
            )
        source, _ = found
        if not is_local_source(source):
            raise StageStop(
                "locate",
                f'module "{name}" uses a remote source ({source}); not supported yet',
                ["remote modules arrive in a later release; fix this resource by hand for now"],
            )
        directory = (directory / source).resolve()
        reasoning.append(f"module {name} source local: {source}")

    block = find_resource_block(directory, match.type, match.name)
    if block is None:
        raise StageStop(
            "locate",
            f'resource "{match.type}" "{match.name}" not found in {_rel(directory, repo)}/',
            ["check that the state matches this checkout (right branch or workspace)"],
        )
    file_rel = _rel(block.file, repo)

    owners: list[str] = []
    codeowners = find_codeowners(repo)
    if codeowners is not None:
        owners = owners_for(codeowners, file_rel)
    if owners:
        reasoning.append(f"owners from {_rel(codeowners, repo)}" if codeowners else "")
    else:
        reasoning.append("no CODEOWNERS rule matches this file")

    loc = Location(
        address=match.address,
        file=file_rel,
        line=block.line,
        module_path=match.module_names,
        state_source=state_label,
        owners=owners,
        drift=None,
        confidence=Confidence.HIGH if owners else Confidence.MEDIUM,
        reasoning=[r for r in reasoning if r],
    )
    return loc, match


def _prefer(matches: list[StateMatch], types: Sequence[str]) -> list[StateMatch]:
    for rtype in types:
        found = [m for m in matches if m.type == rtype]
        if found:
            return found
    return []


def _by_type(state: dict[str, Any], types: Sequence[str]) -> list[StateMatch]:
    for rtype in types:
        found = find_by_type(state, rtype)
        if found:
            return found
    return []


def _load_state(
    repo: Path,
    tf_root: Path,
    config: Config,
    override: Path | None,
    s3_fetch: S3Fetch | None,
) -> tuple[dict[str, Any], str]:
    if override is not None:
        path = override if override.is_absolute() else (Path.cwd() / override)
        return load_state(path), _rel(path, repo)
    tf = config.terraform
    if tf.backend == "s3":
        backend = find_s3_backend(tf_root)
        if backend is None:
            raise StageStop(
                "locate",
                f'no backend "s3" block found in {_rel(tf_root, repo) or "."}/',
                ["set terraform.root to the directory with the backend block, or pass --state"],
            )
        if s3_fetch is None:
            raise StageStop(
                "locate",
                "the S3 state needs AWS access, which a dry run does not use",
                ["pass a local state copy with --state (never commit it), or drop --dry-run"],
            )
        raw = s3_fetch(backend.bucket, backend.key, backend.region or config.aws.region)
        return parse_state(raw), f"s3://{backend.bucket}/{backend.key}"
    path = repo / (tf.state_path or str(Path(tf.root) / "terraform.tfstate"))
    return load_state(path), _rel(path, repo)


def _rel(path: Path | None, repo: Path) -> str:
    if path is None:
        return ""
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
