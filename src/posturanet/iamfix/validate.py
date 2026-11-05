"""Validation for IAM least-privilege fixes (FR-21..FR-26, FR-51).

guardrails, re-check of the edited code, invariants (nothing new allowed; every used action
still allowed), fmt, init/validate, plan scope (only the policy, in place), and a plan check
that the planned policy JSON passes the control and allows exactly the edited actions.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from posturanet.iamfix import recheck_code
from posturanet.iamfix.doc import PolicyDoc, reparse, statements_from_json
from posturanet.iamfix.shrink import ServiceUse, StatementChange, check_invariants, recheck
from posturanet.models import Check, CheckResult, Config, Diff, ValidationReport
from posturanet.validate.guardrails import check_paths
from posturanet.validate.plan_scope import check_scope, resource_change
from posturanet.validate.runner import _IGNORE, _check, fmt_check
from posturanet.validate.tf import TerraformRunner, TfResult


def validate_iam_fix(
    *,
    repo: Path,
    control: str,
    doc: PolicyDoc,
    address: str,
    diff: Diff,
    changes: list[StatementChange],
    usage: dict[str, ServiceUse],
    extra: list[str],
    config: Config,
    tf: TerraformRunner,
    state_path: Path | None,
    offline: bool,
) -> ValidationReport:
    cfg = config
    checks = [check_paths(diff, cfg.validation.allowed_paths, cfg.contracts.dir)]
    new_text = diff.files[0].new_content
    checks.append(recheck_code(control, doc, new_text))
    bad = check_invariants(changes, usage, extra)
    checks.append(
        Check(
            id="invariants",
            required=True,
            result=CheckResult.FAIL if bad else CheckResult.PASS,
            detail="; ".join(bad[:3])
            if bad
            else "allows nothing new; every used action is still allowed",
            model_scope="action names and wildcards in the edited statements; "
            "resources and conditions unchanged",
        )
    )
    edited = reparse(doc, new_text.replace("\r\n", "\n"))
    expected = sorted({a.lower() for s in edited if s.effect == "Allow" for a in s.actions or []})

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
            checks += _plan(tf, work, cfg, state_path, address, control, expected)
    return ValidationReport(checks=checks)


def _plan(
    tf: TerraformRunner,
    work: Path,
    cfg: Config,
    state_path: Path | None,
    address: str,
    control: str,
    expected: list[str],
) -> list[Check]:
    tf_dir = work / cfg.terraform.root
    if cfg.validation.plan == "skip":
        why = "validation.plan is skip"
        return [
            Check(id="plan_scope", required=True, result=CheckResult.SKIPPED, detail=why),
            Check(id="plan_matches", required=True, result=CheckResult.SKIPPED, detail=why),
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
    checks.append(check_scope(plan, address))
    checks.append(plan_matches(resource_change(plan, address), control, expected))
    return checks


def plan_matches(rc: dict[str, Any] | None, control: str, expected: list[str]) -> Check:
    def fail(detail: str, result: CheckResult = CheckResult.FAIL) -> Check:
        return Check(id="plan_matches", required=True, result=result, detail=detail)

    if rc is None:
        return fail("the policy is not in the plan")
    change = rc.get("change") or {}
    if (change.get("after_unknown") or {}).get("policy"):
        return fail("the planned policy is unknown until apply", CheckResult.ERROR)
    before, after = change.get("before") or {}, change.get("after") or {}
    policy = after.get("policy")
    if not isinstance(policy, str):
        return fail("the plan has no policy document")
    try:
        statements = statements_from_json(policy)
    except (json.JSONDecodeError, AttributeError):
        return fail("the planned policy isn't valid JSON")
    ok, detail = recheck(control, statements)
    if not ok:
        return fail(detail.replace("changed policy", "planned policy"))
    planned = sorted(
        {
            str(a).lower()
            for s in statements
            if s.get("Effect") == "Allow"
            for a in s.get("Action") or []
        }
    )
    if planned != expected:
        return fail("planned Allow actions differ from the edited code")
    extra = sorted(
        k
        for k in set(before) | set(after)
        if k not in ("policy", "tags_all") and before.get(k) != after.get(k)
    )
    if extra:
        return fail("plan also changes " + ", ".join(extra) + " on the policy; resolve that first")
    return Check(
        id="plan_matches",
        required=True,
        result=CheckResult.PASS,
        detail=f"planned policy passes {control}; {len(planned)} allowed action(s) match the code",
    )
