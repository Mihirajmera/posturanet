"""Validation for attribute fixes (FR-21..FR-26, FR-48).

Same gates as a security-group fix, minus the contract invariants: guardrails, fmt,
init/validate, plan scope (only the target, updated in place), and a plan check that the
target's planned attributes satisfy the control and that nothing else on it changes.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from posturanet.configfix.catalog import ConfigFix
from posturanet.configfix.hcl_attrs import Unsupported, satisfied
from posturanet.models import Check, CheckResult, Config, Diff, ValidationReport
from posturanet.validate.guardrails import check_paths
from posturanet.validate.plan_scope import check_scope, resource_change
from posturanet.validate.runner import _IGNORE, _check, fmt_check
from posturanet.validate.tf import TerraformRunner, TfResult

# Attributes the provider recomputes on every update; a change to them isn't ours.
_ALWAYS_CHANGES = {"tags_all"}


def validate_config_fix(
    *,
    repo: Path,
    fix: ConfigFix,
    address: str,
    file: str,
    line: int,
    diff: Diff,
    config: Config,
    tf: TerraformRunner,
    state_path: Path | None,
    offline: bool,
    create: bool = False,
) -> ValidationReport:
    """With `create`, the target is a new resource: the plan must add it and change nothing."""
    cfg = config
    checks = [check_paths(diff, cfg.validation.allowed_paths, cfg.contracts.dir)]

    new_text = next((f.new_content for f in diff.files if f.path == file), None)
    checks.append(_recheck_code(fix, new_text, line))

    with tempfile.TemporaryDirectory(prefix="posturanet-") as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(repo, work, ignore=_IGNORE)
        checks.append(fmt_check(tf, work, diff))
        for f in diff.files:
            (work / f.path).write_bytes(f.new_content.encode("utf-8"))

        if offline:
            reason = "dry run: no terraform init/plan"
            for cid in ("validate", "plan_scope", "plan_matches"):
                checks.append(
                    Check(id=cid, required=True, result=CheckResult.SKIPPED, detail=reason)
                )
        else:
            checks += _plan_checks(
                tf, work / cfg.terraform.root, work, fix, address, cfg, state_path, create
            )
    return ValidationReport(checks=checks)


def _recheck_code(fix: ConfigFix, new_text: str | None, line: int) -> Check:
    if new_text is None:
        return Check(id="recheck", required=True, result=CheckResult.FAIL, detail="no file changed")
    try:
        unmet = [c.describe() for c in fix.changes if not satisfied(new_text, line, c)]
    except Unsupported as exc:
        return Check(id="recheck", required=True, result=CheckResult.FAIL, detail=str(exc))
    if unmet:
        return Check(
            id="recheck",
            required=True,
            result=CheckResult.FAIL,
            detail="changed code still fails: " + "; ".join(unmet),
        )
    return Check(
        id="recheck",
        required=True,
        result=CheckResult.PASS,
        detail=f"changed code meets {fix.control} ({len(fix.changes)} setting(s))",
    )


def _plan_checks(
    tf: TerraformRunner,
    tf_dir: Path,
    work: Path,
    fix: ConfigFix,
    address: str,
    cfg: Config,
    state_path: Path | None,
    create: bool = False,
) -> list[Check]:
    if cfg.validation.plan == "skip":
        skipped = "validation.plan is skip"
        return [
            Check(id="plan_scope", required=True, result=CheckResult.SKIPPED, detail=skipped),
            Check(id="plan_matches", required=True, result=CheckResult.SKIPPED, detail=skipped),
        ]
    init = tf.init(tf_dir, backend=True)
    if not init.ok:
        return [
            _check("validate", init),
            Check(id="plan_scope", required=True, result=CheckResult.SKIPPED, detail="init failed"),
            Check(
                id="plan_matches", required=True, result=CheckResult.SKIPPED, detail="init failed"
            ),
        ]
    checks = [_check("validate", tf.validate(tf_dir))]

    state: Path | None = None
    if cfg.terraform.backend == "local":
        if state_path is not None:
            state = state_path.resolve()
        elif cfg.terraform.state_path:
            state = work / cfg.terraform.state_path
    res, plan = tf.plan_json(tf_dir, state)
    if plan is None:
        checks.append(_check("plan_scope", res if not res.ok else TfResult(False, "no plan")))
        checks.append(
            Check(id="plan_matches", required=True, result=CheckResult.SKIPPED, detail="no plan")
        )
        return checks

    checks.append(check_scope(plan, address, expect="create" if create else "update"))
    rc = resource_change(plan, address)
    checks.append(plan_matches(rc, fix, create=create))
    return checks


def plan_matches(rc: dict[str, Any] | None, fix: ConfigFix, *, create: bool = False) -> Check:
    if rc is None:
        return Check(
            id="plan_matches",
            required=True,
            result=CheckResult.FAIL,
            detail="the target is not in the plan",
        )
    change = rc.get("change") or {}
    before, after = change.get("before") or {}, change.get("after") or {}
    unknown = change.get("after_unknown") or {}

    for c in fix.changes:
        if get_path(unknown, c.path) is True:
            return Check(
                id="plan_matches",
                required=True,
                result=CheckResult.ERROR,
                detail=f"{c.path} is unknown until apply",
            )
        value = get_path(after, c.path)
        if not c.satisfied_by(value):
            return Check(
                id="plan_matches",
                required=True,
                result=CheckResult.FAIL,
                detail=f"planned {c.path} is {value!r}; needs {c.describe()}",
            )

    if create:
        return Check(
            id="plan_matches",
            required=True,
            result=CheckResult.PASS,
            detail=f"planned {', '.join(c.path for c in fix.changes)} meet {fix.control} "
            "on the new resource",
        )
    ours = {c.path.split(".", 1)[0] for c in fix.changes}
    extra = sorted(
        k
        for k in set(before) | set(after)
        if k not in ours and k not in _ALWAYS_CHANGES and before.get(k) != after.get(k)
    )
    if extra:
        return Check(
            id="plan_matches",
            required=True,
            result=CheckResult.FAIL,
            detail="plan also changes "
            + ", ".join(extra)
            + " on the target (drift or provider defaults); resolve that first",
        )
    return Check(
        id="plan_matches",
        required=True,
        result=CheckResult.PASS,
        detail=f"planned {', '.join(c.path for c in fix.changes)} meet {fix.control}; "
        "nothing else on the target changes",
    )


def get_path(obj: Any, path: str) -> Any:
    """Follow a dotted path through plan JSON, where nested blocks are one-item lists."""
    for part in path.split("."):
        if isinstance(obj, list):
            if len(obj) != 1:
                return None
            obj = obj[0]
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj
