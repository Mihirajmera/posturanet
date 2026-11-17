"""Diffs and static validation for CloudFormation fixes (FR-21..FR-26).

A CloudFormation change set would be the template's own preview, but creating one needs
`cloudformation:CreateChangeSet`, a write PosturaNet doesn't hold (NFR-2). So the template is
validated statically: it parses, only the target resource changed, the edited resource passes
the control and the contract, and (with AWS access) the repo template still matches what the
stack deployed (`cloudformation:GetTemplate`, read-only). `cfn-lint` runs when installed.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from posturanet.aws.session import ClientFactory
from posturanet.cfn.edit import (
    CfnPolicy,
    CfnSecurityGroup,
    iam_edit,
    owned_ingress,
    parse_policy,
    parse_sg,
    render_sg,
    s3_block_public_access,
    s3_flags,
)
from posturanet.cfn.locate import CfnResource
from posturanet.cfn.template import TemplateError, get, parse, value
from posturanet.errors import StageStop
from posturanet.iamfix.shrink import (
    ServiceUse,
    StatementChange,
    check_invariants,
    recheck,
    targeted,
)
from posturanet.models import (
    BehaviorContract,
    Check,
    CheckResult,
    Config,
    Diff,
    FileChange,
    ValidationReport,
)
from posturanet.synth.hcl_render import rules_diff, unified_diff
from posturanet.synth.sg_z3 import Synthesis
from posturanet.validate.guardrails import check_paths
from posturanet.validate.invariants import MODEL_SCOPE, check_contract
from posturanet.validate.recheck import recheck as sg_recheck
from posturanet.validate.recheck import supported

CHANGESET_NOTE = "needs cloudformation:CreateChangeSet (a write); validated statically"


def _rel(res: CfnResource, repo: Path) -> str:
    return res.template.path.resolve().relative_to(repo.resolve()).as_posix()


def _diff(repo: Path, res: CfnResource, new: str, summary: str, generator: str) -> Diff:
    rel = _rel(res, repo)
    udiff = unified_diff(rel, res.template.text, new)
    return Diff(
        target_address=res.address,
        files=[FileChange(path=rel, unified_diff=udiff, new_content=res.template.on_disk(new))],
        summary=summary,
        generator=generator,
        sha256=hashlib.sha256(udiff.encode("utf-8")).hexdigest(),
    )


# --- diffs


def sg_diff(repo: Path, sg: CfnSecurityGroup, synth: Synthesis) -> Diff:
    res = sg.res
    diff = rules_diff(
        _rel(res, repo), sg.text, render_sg(sg, synth), res.template.crlf, synth, res.address
    )
    return diff.model_copy(update={"generator": "template:sg_ingress@1:cloudformation"})


def s3_diff(repo: Path, res: CfnResource) -> tuple[Diff, list[str]]:
    new, changed, already = s3_block_public_access(res)
    if not changed:
        raise StageStop(
            "fix",
            "the template already blocks public access, so the live bucket has drifted",
            ["deploy the stack through your pipeline; the fix is already in the code"],
            why="PosturaNet fixes code, and this code is already fixed; the live bucket isn't",
        )
    summary = f"{res.logical_id} PublicAccessBlockConfiguration: " + ", ".join(
        f"{n}=true" for n in changed
    )
    return _diff(repo, res, new, summary, "template:s3_public@1:cloudformation"), already


def iam_diff(repo: Path, policy: CfnPolicy, changes: list[StatementChange]) -> Diff:
    new = iam_edit(policy, {c.statement.index: c.after for c in changes})
    removed = sorted({p for c in changes for p in c.removed})
    kept = sum(len(c.after) for c in changes)
    summary = f"{', '.join(removed)} → {kept} used action(s) in {len(changes)} statement(s)"
    diff = _diff(repo, policy.res, new, summary, "template:iam_least_privilege@1:cloudformation")
    return diff.model_copy(
        update={
            "rules_before": [a for c in changes for a in c.before],
            "rules_after": [a for c in changes for a in c.after],
        }
    )


# --- validation


def _edited(res: CfnResource, diff: Diff) -> CfnResource | str:
    """The target resource in the edited template, or why it can't be read."""
    try:
        t = parse(diff.files[0].new_content, res.template.path)
    except TemplateError as exc:
        return str(exc)
    node = t.resources.get(res.logical_id)
    if node is None:
        return f"{res.logical_id} is missing from the edited template"
    return CfnResource(res.stack, res.logical_id, res.type, t, node, res.line)


def _own(resources: dict[str, Any], logical_id: str) -> dict[str, Any]:
    """The resource and any SecurityGroupIngress resources that add rules to it."""
    keep = {logical_id, *owned_ingress(resources, logical_id)}
    return {k: v for k, v in resources.items() if k in keep}


def _scope(res: CfnResource, edited: CfnResource) -> Check:
    def rest(root: Any) -> Any:
        out = dict(value(root))
        own = _own(out["Resources"], res.logical_id)
        out["Resources"] = {k: v for k, v in out["Resources"].items() if k not in own}
        return out

    if rest(res.template.root) != rest(edited.template.root):
        return Check(
            id="template_scope",
            required=True,
            result=CheckResult.FAIL,
            detail="the edit changes more than the target resource",
        )
    before = _own(value(get(res.template.root, "Resources")), res.logical_id)
    after = _own(value(get(edited.template.root, "Resources")), res.logical_id)
    if value(get(res.node, "Type")) != value(get(edited.node, "Type")):
        return Check(
            id="template_scope",
            required=True,
            result=CheckResult.FAIL,
            detail="the edit changes the resource Type (a replacement)",
        )
    return Check(
        id="template_scope",
        required=True,
        result=CheckResult.PASS if before != after else CheckResult.FAIL,
        detail=f"only {res.logical_id} changes; the template parses"
        if before != after
        else "the edit changes nothing",
    )


def _drift(res: CfnResource, aws: ClientFactory | None, offline: bool) -> Check:
    def check(result: CheckResult, detail: str) -> Check:
        return Check(id="drift", required=True, result=result, detail=detail)

    if offline or aws is None:
        return check(CheckResult.SKIPPED, "dry run: deployed template not read")
    try:
        body = aws("cloudformation").get_template(StackName=res.stack, TemplateStage="Original")[
            "TemplateBody"
        ]
    except Exception as exc:  # botocore ClientError; boto3 is only imported in aws/
        return check(CheckResult.ERROR, f"cloudformation:GetTemplate failed: {exc}")
    if isinstance(body, str):
        try:
            deployed = value(get(parse(body, res.template.path).root, "Resources"))
        except TemplateError:
            return check(CheckResult.ERROR, "the deployed template could not be read")
    else:
        deployed = body.get("Resources") or {}
    repo_side = _own(value(get(res.template.root, "Resources")), res.logical_id)
    if _own(deployed, res.logical_id) != repo_side:
        return check(
            CheckResult.FAIL,
            f"{res.logical_id} in the repo differs from stack {res.stack}; deploy or pull first",
        )
    return check(CheckResult.PASS, f"{res.logical_id} matches the template stack {res.stack} runs")


def _cfn_lint(diff: Diff, timeout_s: int) -> Check:
    exe = shutil.which("cfn-lint")
    if exe is None:
        return Check(
            id="cfn-lint", required=False, result=CheckResult.SKIPPED, detail="not installed"
        )
    with tempfile.TemporaryDirectory(prefix="posturanet-") as tmp:
        path = Path(tmp) / Path(diff.files[0].path).name
        path.write_bytes(diff.files[0].new_content.encode("utf-8"))
        try:
            proc = subprocess.run(  # noqa: S603 - allowlisted tool, list args
                [exe, str(path)], capture_output=True, text=True, timeout=timeout_s, check=False
            )
        except subprocess.TimeoutExpired:
            return Check(
                id="cfn-lint", required=False, result=CheckResult.ERROR, detail="timed out"
            )
    ok = proc.returncode == 0
    return Check(
        id="cfn-lint",
        required=False,
        result=CheckResult.PASS if ok else CheckResult.FAIL,
        detail="" if ok else "reported issues (not blocking)",
    )


def _validate(
    res: CfnResource,
    diff: Diff,
    config: Config,
    aws: ClientFactory | None,
    offline: bool,
    specific: Callable[[CfnResource], list[Check]],
) -> ValidationReport:
    checks = [check_paths(diff, config.validation.allowed_paths, config.contracts.dir)]
    edited = _edited(res, diff)
    if isinstance(edited, str):
        checks.append(
            Check(id="template_scope", required=True, result=CheckResult.FAIL, detail=edited)
        )
    else:
        checks.append(_scope(res, edited))
        try:
            checks += specific(edited)
        except StageStop as exc:
            checks.append(
                Check(id="recheck", required=True, result=CheckResult.FAIL, detail=exc.reason)
            )
    checks.append(_drift(res, aws, offline))
    checks.append(
        Check(id="changeset", required=False, result=CheckResult.SKIPPED, detail=CHANGESET_NOTE)
    )
    checks.append(_cfn_lint(diff, config.validation.timeout_s))
    return ValidationReport(checks=checks)


def validate_sg(
    res: CfnResource,
    diff: Diff,
    synth: Synthesis,
    contract: BehaviorContract,
    control: str,
    config: Config,
    aws: ClientFactory | None,
    *,
    offline: bool,
) -> ValidationReport:
    expected = sorted({*synth.kept, *synth.added})

    def specific(edited: CfnResource) -> list[Check]:
        rules = parse_sg(edited).rules()
        results = check_contract(rules, contract)
        failed = [r for r in results if not r.holds]
        out = [
            Check(
                id="template_matches",
                required=True,
                result=CheckResult.PASS if rules == expected else CheckResult.FAIL,
                detail="template ingress equals the synthesized rules"
                if rules == expected
                else "template ingress differs from the synthesized rules",
            ),
            Check(
                id="invariants",
                required=True,
                result=CheckResult.FAIL if failed else CheckResult.PASS,
                detail=f"{len(results)}/{len(results)} hold on the edited template"
                if not failed
                else "; ".join(f"{r.id}: {r.detail}" for r in failed),
                model_scope=MODEL_SCOPE,
            ),
        ]
        if supported(control):
            ok, detail = sg_recheck(control, rules)
            out.append(
                Check(
                    id="recheck",
                    required=True,
                    result=CheckResult.PASS if ok else CheckResult.FAIL,
                    detail=detail.replace("planned", "edited template"),
                )
            )
        else:
            out.append(
                Check(
                    id="recheck",
                    required=True,
                    result=CheckResult.SKIPPED,
                    detail=f"no re-check for {control} yet",
                )
            )
        return out

    return _validate(res, diff, config, aws, offline, specific)


def validate_s3(
    res: CfnResource,
    diff: Diff,
    control: str,
    config: Config,
    aws: ClientFactory | None,
    *,
    offline: bool,
) -> ValidationReport:
    def specific(edited: CfnResource) -> list[Check]:
        unmet = [k for k, v in s3_flags(edited).items() if v is not True and v != "true"]
        return [
            Check(
                id="recheck",
                required=True,
                result=CheckResult.FAIL if unmet else CheckResult.PASS,
                detail="edited template still fails: " + ", ".join(unmet) + " not true"
                if unmet
                else f"edited template meets {control} (4 setting(s))",
            )
        ]

    return _validate(res, diff, config, aws, offline, specific)


def validate_iam(
    res: CfnResource,
    diff: Diff,
    control: str,
    changes: list[StatementChange],
    usage: dict[str, ServiceUse],
    extra: list[str],
    config: Config,
    aws: ClientFactory | None,
    *,
    offline: bool,
) -> ValidationReport:
    bad = check_invariants(changes, usage, extra)

    def specific(edited: CfnResource) -> list[Check]:
        statements = parse_policy(edited).statements
        as_json: list[dict[str, object]] = [
            {"Sid": s.sid, "Effect": s.effect, "Action": s.actions or [], "Resource": s.resources}
            for s in statements
        ]
        ok, detail = recheck(control, as_json)
        if ok and any(
            targeted(control, a) for s in statements if s.effect == "Allow" for a in s.actions or []
        ):
            ok, detail = False, f"{control} wildcard still in the edited template"
        return [
            Check(
                id="recheck",
                required=True,
                result=CheckResult.PASS if ok else CheckResult.FAIL,
                detail=detail.replace("changed policy", "edited template"),
            ),
            Check(
                id="invariants",
                required=True,
                result=CheckResult.FAIL if bad else CheckResult.PASS,
                detail="; ".join(bad[:3])
                if bad
                else "allows nothing new; every used action is still allowed",
                model_scope="action names and wildcards in the edited statements; "
                "resources and conditions unchanged",
            ),
        ]

    return _validate(res, diff, config, aws, offline, specific)
