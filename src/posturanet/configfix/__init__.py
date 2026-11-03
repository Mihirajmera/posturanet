"""Attribute fixes: change literal settings on one resource, in place (FR-48).

The catalog says which control maps to which Terraform attribute. `edit_resource` applies it
to the located block and returns the diff; validation and delivery reuse the shared gates.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from posturanet.configfix.catalog import ConfigFix, catalog, controls, fixes_for
from posturanet.configfix.hcl_attrs import EditResult, Unsupported, applies, apply_changes
from posturanet.errors import StageStop
from posturanet.models import Diff, FileChange
from posturanet.synth.hcl_render import unified_diff

_BY_HAND = "edit this resource by hand; PosturaNet only edits literal values in static blocks"


def edit_resource(
    repo: Path, file: str, line: int, address: str, fix: ConfigFix
) -> tuple[Diff, EditResult, str]:
    """(diff, edit, original file text). Raises StageStop when the fix can't be applied."""
    original = (repo / file).read_bytes().decode("utf-8")
    try:
        ok, why = applies(original, line, fix.when)
        if not ok:
            raise StageStop(
                "fix",
                f"the {fix.control} fix doesn't apply here: {why}",
                ["fix this resource by hand"],
            )
        edit = apply_changes(original, line, fix.changes)
    except Unsupported as exc:
        raise StageStop("fix", str(exc), [_BY_HAND]) from exc
    if not edit.changed:
        raise StageStop(
            "fix",
            f"the code already meets {fix.control}, so the live resource has drifted",
            [
                "run terraform plan: it should show the fix pending; apply it in your pipeline",
                "then let Security Hub re-evaluate the control",
            ],
            why="PosturaNet fixes code, and this code is already fixed; the live resource isn't",
        )
    udiff = unified_diff(file, original.replace("\r\n", "\n"), edit.text.replace("\r\n", "\n"))
    diff = Diff(
        target_address=address,
        files=[FileChange(path=file, unified_diff=udiff, new_content=edit.text)],
        summary="; ".join(edit.changed),
        rules_before=[],
        rules_after=[],
        generator="template:config_attribute@1",
        sha256=hashlib.sha256(udiff.encode("utf-8")).hexdigest(),
    )
    return diff, edit, original


__all__ = ["ConfigFix", "catalog", "controls", "edit_resource", "fixes_for"]
