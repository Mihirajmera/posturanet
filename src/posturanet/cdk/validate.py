"""Diffs to CDK source and their validation (FR-21..FR-26).

The fix edits the program, never the synthesized template. Validation re-reads the edited
source, then (outside dry runs) synthesizes the edited app with `cdk synth --no-lookups` and
runs the CloudFormation checks on the new template: only the target resource changed, the
rules are the synthesized ones, the contract holds and the control passes. The deployed
template is compared with `cloudformation:GetTemplate` (read-only). `cdk diff` is not run: it
signs in with the CDK CLI's own credentials and bootstrap roles, which PosturaNet doesn't use.
"""

from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from posturanet.aws.session import ClientFactory
from posturanet.cdk import source
from posturanet.cdk.app import CdkRunner, CdkTarget, SubprocessCdk, in_template, stack_template
from posturanet.cdk.source import Construct
from posturanet.cfn.edit import parse_policy, parse_sg
from posturanet.cfn.locate import CfnResource
from posturanet.cfn.template import Template, value
from posturanet.cfn.validate import Checks, drift, iam_checks, s3_checks, sg_checks
from posturanet.errors import StageStop
from posturanet.iamfix.shrink import ServiceUse, StatementChange
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

CDK_DIFF_NOTE = (
    "not run: it needs the CDK CLI's own credentials and bootstrap roles; the deployed "
    "template is read with the read-only role instead"
)
_HAND = "fix this construct by hand"


def _rel(t: CdkTarget, repo: Path) -> str:
    return t.construct.file.resolve().relative_to(repo.resolve()).as_posix()


def _diff(repo: Path, t: CdkTarget, new: str, summary: str, generator: str) -> Diff:
    rel = _rel(t, repo)
    udiff = unified_diff(rel, t.construct.text, new)
    return Diff(
        target_address=t.address,
        files=[FileChange(path=rel, unified_diff=udiff, new_content=t.construct.on_disk(new))],
        summary=summary,
        generator=generator,
        sha256=hashlib.sha256(udiff.encode("utf-8")).hexdigest(),
    )


# --- diffs


def sg_diff(repo: Path, t: CdkTarget, synth: Synthesis) -> Diff:
    c = t.construct
    calls = source.ingress_calls(c)
    in_source = sorted({source.norm(k.rule) for k in calls})
    sg = parse_sg(t.res)
    in_template_ = sorted({source.norm(r) for r in sg.rules()})
    # Group peers (no CIDR rule) and standalone ingress come from `connections`, not literals.
    foreign = [e.resource or "an ingress entry" for e in sg.entries if e.resource or not e.rules]
    if foreign:
        raise StageStop(
            "fix",
            f"{t.construct_path} gets ingress from {', '.join(foreign)} in the template, "
            "which no literal addIngressRule call explains",
            [f"rules from connections.allowFrom or security-group peers aren't edited; {_HAND}"],
            unknown=True,
        )
    if in_source != in_template_:
        raise StageStop(
            "fix",
            f"{t.construct_path} has {len(in_template_)} ingress rule(s) in the template but "
            f"{len(in_source)} literal addIngressRule call(s) on `{c.var}` in {c.file.name}",
            [
                "rules from connections.allowFrom, other files or computed values aren't "
                f"edited; {_HAND}",
            ],
            unknown=True,
        )
    new = source.render_sg(c, calls, synth.added)
    diff = rules_diff(_rel(t, repo), c.text, new, c.crlf, synth, t.address)
    return diff.model_copy(update={"generator": "template:sg_ingress@1:cdk"})


def s3_diff(repo: Path, t: CdkTarget) -> Diff:
    new, summary = source.render_s3(t.construct)
    return _diff(repo, t, new, f"{t.construct.construct_id} {summary}", "template:s3_public@1:cdk")


def _mapped(t: CdkTarget) -> list[source.SourceStatement]:
    """The source statements, checked one-for-one against the synthesized ones."""
    in_source = source.statements(t.construct)
    in_template_ = parse_policy(t.res).statements
    same = len(in_source) == len(in_template_) and all(
        (None if s.actions is None else set(s.actions))
        == (None if p.actions is None else set(p.actions))
        for s, p in zip(in_source, in_template_, strict=True)
    )
    if not same:
        raise StageStop(
            "fix",
            f"the {len(in_template_)} synthesized statement(s) of {t.construct_path} don't map "
            f"one-for-one to the {len(in_source)} PolicyStatement(s) written in the construct",
            [
                "statements added with addStatements, built elsewhere, or merged by CDK's "
                f"policy minimization can't be traced to a line; {_HAND}",
            ],
            unknown=True,
        )
    return in_source


def iam_diff(repo: Path, t: CdkTarget, changes: list[StatementChange]) -> Diff:
    sts = _mapped(t)
    new = source.render_iam(t.construct, sts, {c.statement.index: c.after for c in changes})
    removed = sorted({p for c in changes for p in c.removed})
    kept = sum(len(c.after) for c in changes)
    summary = f"{', '.join(removed)} → {kept} used action(s) in {len(changes)} statement(s)"
    diff = _diff(repo, t, new, summary, "template:iam_least_privilege@1:cdk")
    return diff.model_copy(
        update={
            "rules_before": [a for c in changes for a in c.before],
            "rules_after": [a for c in changes for a in c.after],
        }
    )


# --- validation

SourceCheck = Callable[[Construct], Check]


def _source_check(ok: bool, detail_ok: str, detail_fail: str) -> Check:
    return Check(
        id="source",
        required=True,
        result=CheckResult.PASS if ok else CheckResult.FAIL,
        detail=detail_ok if ok else detail_fail,
    )


def _scope(before: CfnResource, after: CfnResource) -> Check:
    def rest(t: Template) -> Any:
        out = dict(value(t.root))
        out["Resources"] = {
            k: v
            for k, v in out["Resources"].items()
            if k != before.logical_id and v.get("Type") != "AWS::CDK::Metadata"
        }
        return out

    if rest(before.template) != rest(after.template):
        detail = "the edit changes more than the target resource in the synthesized template"
        ok = False
    elif after.type != before.type:
        detail, ok = "the edit changes the resource Type (a replacement)", False
    else:
        ok = value(before.node) != value(after.node)
        detail = f"only {before.logical_id} changes" if ok else "the template doesn't change"
    return Check(
        id="template_scope",
        required=True,
        result=CheckResult.PASS if ok else CheckResult.FAIL,
        detail=detail,
    )


def _synth_edited(
    t: CdkTarget, diff: Diff, config: Config, runner: CdkRunner | None
) -> CfnResource | Check:
    """The target resource synthesized from the edited app. The edited file is written in
    place for the synth and always put back."""

    def fail(result: CheckResult, detail: str) -> Check:
        return Check(id="cdk_synth", required=True, result=result, detail=detail)

    path = t.construct.file
    original = path.read_bytes()
    if original.decode("utf-8", errors="replace").replace("\r\n", "\n") != t.construct.text:
        return fail(CheckResult.ERROR, f"{path.name} changed while PosturaNet was running")
    run = runner or SubprocessCdk(config.cdk.binary, config.validation.timeout_s)
    with tempfile.TemporaryDirectory(prefix="posturanet-cdk-") as tmp:
        try:
            path.write_bytes(diff.files[0].new_content.encode("utf-8"))
            err = run.synth(t.app, Path(tmp))
        finally:
            path.write_bytes(original)
        if err is not None:
            return fail(CheckResult.FAIL, f"the edited app doesn't synthesize: {err}")
        tpl = stack_template(Path(tmp), "cdk synth", t.res.stack)
        res = in_template(tpl, t.res.stack, t.res.logical_id) if not isinstance(tpl, str) else tpl
    if isinstance(res, str):
        return fail(CheckResult.FAIL, f"{res} after the edit (the logical id changed)")
    return res


def _validate(
    t: CdkTarget,
    diff: Diff,
    config: Config,
    aws: ClientFactory | None,
    runner: CdkRunner | None,
    offline: bool,
    source_check: SourceCheck,
    specific: Checks,
) -> ValidationReport:
    checks = [check_paths(diff, config.validation.allowed_paths, config.contracts.dir)]
    try:
        edited_src = source.rescan(t.construct, diff.files[0].new_content.replace("\r\n", "\n"))
        checks.append(source_check(edited_src))
    except StageStop as exc:
        checks.append(Check(id="source", required=True, result=CheckResult.FAIL, detail=exc.reason))
    if offline:
        checks.append(
            Check(
                id="cdk_synth",
                required=True,
                result=CheckResult.SKIPPED,
                detail="dry run: the edited app was not synthesized",
            )
        )
    else:
        edited = _synth_edited(t, diff, config, runner)
        if isinstance(edited, Check):
            checks.append(edited)
        else:
            checks.append(
                Check(
                    id="cdk_synth",
                    required=True,
                    result=CheckResult.PASS,
                    detail="the edited app synthesizes (--no-lookups, no AWS credentials)",
                )
            )
            checks.append(_scope(t.res, edited))
            try:
                checks += specific(edited)
            except StageStop as exc:
                checks.append(
                    Check(id="recheck", required=True, result=CheckResult.FAIL, detail=exc.reason)
                )
    checks.append(drift(t.res, aws, offline))
    checks.append(
        Check(id="cdk_diff", required=False, result=CheckResult.SKIPPED, detail=CDK_DIFF_NOTE)
    )
    return ValidationReport(checks=checks)


def validate_sg(
    t: CdkTarget,
    diff: Diff,
    synth: Synthesis,
    contract: BehaviorContract,
    control: str,
    config: Config,
    aws: ClientFactory | None,
    runner: CdkRunner | None,
    *,
    offline: bool,
) -> ValidationReport:
    expected = sorted({source.norm(r) for r in [*synth.kept, *synth.added]})

    def check(c: Construct) -> Check:
        ok = source.source_rules(c) == expected
        return _source_check(
            ok, "edited source has exactly the synthesized rules", "edited source rules differ"
        )

    specific = sg_checks(synth, contract, control)
    return _validate(t, diff, config, aws, runner, offline, check, specific)


def validate_s3(
    t: CdkTarget,
    diff: Diff,
    control: str,
    config: Config,
    aws: ClientFactory | None,
    runner: CdkRunner | None,
    *,
    offline: bool,
) -> ValidationReport:
    def check(c: Construct) -> Check:
        return _source_check(
            source.blocks_all(c), "edited source sets BLOCK_ALL", "edited source isn't BLOCK_ALL"
        )

    return _validate(t, diff, config, aws, runner, offline, check, s3_checks(control))


def validate_iam(
    t: CdkTarget,
    diff: Diff,
    control: str,
    changes: list[StatementChange],
    usage: dict[str, ServiceUse],
    extra: list[str],
    config: Config,
    aws: ClientFactory | None,
    runner: CdkRunner | None,
    *,
    offline: bool,
) -> ValidationReport:
    before = [s.actions for s in source.statements(t.construct)]
    for ch in changes:
        before[ch.statement.index] = ch.after

    def check(c: Construct) -> Check:
        ok = [s.actions for s in source.statements(c)] == before
        return _source_check(
            ok, "edited statements have exactly the kept actions", "edited actions differ"
        )

    specific = iam_checks(control, changes, usage, extra)
    return _validate(t, diff, config, aws, runner, offline, check, specific)
