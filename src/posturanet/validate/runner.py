"""Validation runner (FR-21..FR-26, architecture doc 9).

Runs in a temp copy of the repo. A required check that fails gives FAIL; one that errors or
is skipped gives INCOMPLETE. Either way no PR is opened.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from posturanet.models import (
    BehaviorContract,
    Check,
    CheckResult,
    Config,
    Diff,
    Finding,
    Location,
    ValidationReport,
)
from posturanet.synth.sg_rules import Rule
from posturanet.synth.sg_z3 import Synthesis
from posturanet.validate.guardrails import check_paths
from posturanet.validate.invariants import MODEL_SCOPE, check_contract
from posturanet.validate.plan_scope import check_scope, planned_rules, resource_change
from posturanet.validate.recheck import recheck, supported
from posturanet.validate.tf import TerraformRunner, TfResult

_IGNORE = shutil.ignore_patterns(".git", ".terraform", ".posturanet", "__pycache__", ".venv")


@dataclass
class ValidationInputs:
    repo: Path
    finding: Finding
    location: Location
    diff: Diff
    contract: BehaviorContract
    synthesis: Synthesis
    config: Config
    state_path: Path | None = None


def _check(id: str, res: TfResult, *, required: bool = True, ok_detail: str = "") -> Check:
    if res.missing:
        return Check(id=id, required=required, result=CheckResult.SKIPPED, detail=res.output)
    if res.timed_out:
        return Check(id=id, required=required, result=CheckResult.ERROR, detail=res.output)
    if res.ok:
        return Check(id=id, required=required, result=CheckResult.PASS, detail=ok_detail)
    return Check(id=id, required=required, result=CheckResult.FAIL, detail=_first_error(res.output))


def _first_error(output: str) -> str:
    for line in output.splitlines():
        text = line.strip().lstrip("│").strip()
        if text.lower().startswith("error"):
            return text[:200]
    return (output.strip().splitlines() or ["failed"])[0][:200]


def validate(inputs: ValidationInputs, tf: TerraformRunner, *, offline: bool) -> ValidationReport:
    cfg = inputs.config
    checks: list[Check] = [
        check_paths(inputs.diff, cfg.validation.allowed_paths, cfg.contracts.dir)
    ]
    expected = sorted({*inputs.synthesis.kept, *inputs.synthesis.added})

    with tempfile.TemporaryDirectory(prefix="posturanet-") as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(inputs.repo, work, ignore=_IGNORE)
        tf_dir = work / cfg.terraform.root

        checks.append(fmt_check(tf, work, inputs.diff))

        for f in inputs.diff.files:
            (work / f.path).write_bytes(f.new_content.encode("utf-8"))

        planned: list[Rule] | None = None
        if offline:
            reason = "dry run: no terraform init/plan"
            checks.append(
                Check(id="validate", required=True, result=CheckResult.SKIPPED, detail=reason)
            )
            checks.append(
                Check(id="plan_scope", required=True, result=CheckResult.SKIPPED, detail=reason)
            )
        else:
            planned = _plan_checks(tf, tf_dir, work, inputs, checks)
        optional = _optional_tools(cfg.validation.optional, work, cfg.validation.timeout_s)

    rules = planned if planned is not None else expected
    source = "planned config" if planned is not None else "synthesized rules (not planned)"
    results = check_contract(rules, inputs.contract)
    failed = [r for r in results if not r.holds]
    checks.append(
        Check(
            id="invariants",
            required=True,
            result=CheckResult.FAIL if failed else CheckResult.PASS,
            detail=(
                f"{len(results)}/{len(results)} hold on {source}"
                if not failed
                else "; ".join(f"{r.id}: {r.detail}" for r in failed)
            ),
            model_scope=MODEL_SCOPE,
        )
    )

    control = inputs.finding.control_id
    if supported(control):
        ok, detail = recheck(control, rules)
        checks.append(
            Check(
                id="recheck",
                required=True,
                result=CheckResult.PASS if ok else CheckResult.FAIL,
                detail=detail if planned is not None else detail.replace("planned", "proposed"),
            )
        )
    else:
        checks.append(
            Check(
                id="recheck",
                required=True,
                result=CheckResult.SKIPPED,
                detail=f"no re-check for {control} yet",
            )
        )

    checks += optional
    return ValidationReport(checks=checks)


def fmt_check(tf: TerraformRunner, work: Path, diff: Diff) -> Check:
    """`terraform fmt -check` on the changed files, before and after writing the change."""
    changed = [f.path for f in diff.files]
    if not tf.available():
        return Check(
            id="fmt", required=True, result=CheckResult.SKIPPED, detail="terraform not installed"
        )
    before = tf.fmt_check(work, changed)
    if before.timed_out or before.missing:
        return _check("fmt", before)
    if not before.ok:
        # The file had formatting issues before this change; fmt can't tell ours apart.
        return Check(
            id="fmt",
            required=False,
            result=CheckResult.SKIPPED,
            detail="file was not fmt-clean before this change",
        )
    for f in diff.files:
        (work / f.path).write_bytes(f.new_content.encode("utf-8"))
    return _check("fmt", tf.fmt_check(work, changed))


def _plan_checks(
    tf: TerraformRunner, tf_dir: Path, work: Path, inputs: ValidationInputs, checks: list[Check]
) -> list[Rule] | None:
    cfg = inputs.config
    if cfg.validation.plan == "skip":
        checks.append(
            Check(
                id="plan_scope",
                required=True,
                result=CheckResult.SKIPPED,
                detail="validation.plan is skip",
            )
        )
        return None
    init = tf.init(tf_dir, backend=True)
    if not init.ok:
        checks.append(_check("validate", init))
        checks.append(
            Check(id="plan_scope", required=True, result=CheckResult.SKIPPED, detail="init failed")
        )
        return None
    checks.append(_check("validate", tf.validate(tf_dir)))

    state: Path | None = None
    if cfg.terraform.backend == "local":
        if inputs.state_path is not None:
            state = inputs.state_path.resolve()
        elif cfg.terraform.state_path:
            state = work / cfg.terraform.state_path
    res, plan = tf.plan_json(tf_dir, state)
    if plan is None:
        checks.append(_check("plan_scope", res if not res.ok else TfResult(False, "no plan")))
        return None

    target = inputs.location.address
    checks.append(check_scope(plan, target))
    rc = resource_change(plan, target)
    if rc is None:
        return None

    before = planned_rules(rc, "before")
    original = sorted({*inputs.synthesis.kept, *inputs.synthesis.removed})
    if before is not None and sorted(set(before)) != original:
        checks.append(
            Check(
                id="drift",
                required=True,
                result=CheckResult.FAIL,
                detail="live ingress differs from the code; resolve drift first",
            )
        )
    else:
        checks.append(
            Check(id="drift", required=True, result=CheckResult.PASS, detail="none on target")
        )

    after = planned_rules(rc, "after")
    expected = sorted({*inputs.synthesis.kept, *inputs.synthesis.added})
    if after is None:
        checks.append(
            Check(
                id="plan_matches",
                required=True,
                result=CheckResult.ERROR,
                detail="planned ingress is unknown until apply",
            )
        )
        return None
    matches = sorted(set(after)) == expected
    checks.append(
        Check(
            id="plan_matches",
            required=True,
            result=CheckResult.PASS if matches else CheckResult.FAIL,
            detail="planned ingress equals the synthesized rules"
            if matches
            else "planned ingress differs from the synthesized rules",
        )
    )
    return after


def _optional_tools(names: list[str], work: Path, timeout_s: int) -> list[Check]:
    out: list[Check] = []
    for name in names:
        exe = shutil.which(name)
        if exe is None:
            out.append(
                Check(id=name, required=False, result=CheckResult.SKIPPED, detail="not installed")
            )
            continue
        args = {"tflint": ["--format", "compact"], "checkov": ["-d", ".", "--compact", "--quiet"]}
        try:
            proc = subprocess.run(  # noqa: S603 - allowlisted tool, list args
                [exe, *args.get(name, [])],
                cwd=work,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            out.append(Check(id=name, required=False, result=CheckResult.ERROR, detail="timed out"))
            continue
        out.append(
            Check(
                id=name,
                required=False,
                result=CheckResult.PASS if proc.returncode == 0 else CheckResult.FAIL,
                detail="" if proc.returncode == 0 else "reported issues (not blocking)",
            )
        )
    return out
