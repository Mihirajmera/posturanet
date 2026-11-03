"""Guardrails on what a change may touch (FR-26)."""

from __future__ import annotations

import fnmatch

from posturanet.models import Check, CheckResult, Diff


def check_paths(diff: Diff, allowed: list[str], contracts_dir: str) -> Check:
    bad = []
    for f in diff.files:
        path = f.path
        if (
            path.startswith(("/", "../"))
            or "/../" in path
            or ":" in path
            or not any(fnmatch.fnmatchcase(path, pat) for pat in allowed)
        ):
            bad.append(path)
    if bad:
        return Check(
            id="guardrails",
            required=True,
            result=CheckResult.FAIL,
            detail="outside validation.allowed_paths: " + ", ".join(bad),
        )
    return Check(
        id="guardrails",
        required=True,
        result=CheckResult.PASS,
        detail=f"{len(diff.files)} file(s) inside allowed paths; contract in {contracts_dir}/",
    )
