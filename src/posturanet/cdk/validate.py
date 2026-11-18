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
from posturanet.cfn.edit import _literal, _prop, attr_applies, owned_ingress, parse_policy, parse_sg
from posturanet.cfn.locate import CfnResource
from posturanet.cfn.template import Template, value
from posturanet.cfn.validate import (
    Checks,
    attr_checks,
    drift,
    iam_checks,
    s3_checks,
    sg_checks,
)
from posturanet.configfix.catalog import ConfigFix
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
from posturanet.synth.sg_rules import Rule, norm_proto
from posturanet.synth.sg_z3 import Synthesis
from posturanet.validate.guardrails import check_paths

CHANGESET_NOTE = (
    "not run on CDK apps: cloudformation.changeset_preview covers CloudFormation templates only"
)
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


def _sg_stop(t: CdkTarget, what: str) -> StageStop:
    return StageStop(
        "fix",
        f"{t.construct_path} {what}",
        [
            f"rules from other files, computed values or other constructs aren't edited; {_HAND}",
        ],
        unknown=True,
    )


def trace_sg(t: CdkTarget) -> source.SgSource:
    """The group's literal ingress in its file, checked against the synthesized template:
    inline CIDR rules ↔ ingress calls, standalone ingress ↔ a literal `CfnSecurityGroupIngress`
    (by construct id) or a group-peer call (by ports). Anything left over stops UNKNOWN."""
    c = t.construct
    src = source.sg_source(c)
    sg = parse_sg(t.res)
    resources = value(t.res.template.root)["Resources"]
    scope = t.construct_path.rsplit("/", 1)[0] + "/"  # children of the L2 construct
    inline: set[Rule] = set()
    peers: list[source.PeerPorts] = []
    l1_seen: set[str] = set()
    for e in sg.entries:
        if e.resource is None:
            if not e.rules:
                raise _sg_stop(t, "has an inline ingress entry with a non-CIDR source")
            inline |= {source.norm(r) for r in e.rules}
            continue
        r = resources.get(e.resource) or {}
        props = r.get("Properties") or {}
        path = str((r.get("Metadata") or {}).get("aws:cdk:path", ""))
        if not e.rules and "SourceSecurityGroupId" in props and path.startswith(scope):
            proto = norm_proto(str(props.get("IpProtocol", "")))
            lo, hi = int(props.get("FromPort", -1)), int(props.get("ToPort", -1))
            peers.append(source.peer_ports(proto, lo, hi))
            continue
        match = [x for x in src.l1 if x.construct_id == path.rsplit("/", 1)[-1]]
        if len(match) == 1 and {source.norm(x) for x in e.rules} == {source.norm(match[0].rule)}:
            l1_seen.add(match[0].construct_id)
            continue
        raise _sg_stop(
            t,
            f"gets ingress from {e.resource} in the template, which no literal ingress call or "
            f"CfnSecurityGroupIngress in {c.file.name} explains",
        )
    if sorted(peers) != sorted(src.peers):
        raise _sg_stop(
            t,
            f"has {len(peers)} security-group peer rule(s) in the template but "
            f"{len(src.peers)} literal peer call(s) on `{c.var}` in {c.file.name}",
        )
    unused = sorted({x.construct_id for x in src.l1} - l1_seen)
    if unused:
        raise _sg_stop(t, f"has no template resource for CfnSecurityGroupIngress {unused[0]}")
    found: list[source.IngressCall | source.L1Inline] = [*src.calls, *src.inline]
    in_source = {source.norm(k.rule) for k in found}
    if in_source != inline:
        what = (
            f"literal securityGroupIngress entr(ies) of {c.construct_id}"
            if c.cls == "CfnSecurityGroup"
            else f"literal ingress call(s) on `{c.var}`"
        )
        raise _sg_stop(
            t,
            f"has {len(inline)} ingress rule(s) in the template but {len(in_source)} {what} "
            f"in {c.file.name}",
        )
    return src


def sg_diff(repo: Path, t: CdkTarget, synth: Synthesis) -> Diff:
    src = trace_sg(t)
    new = source.render_sg(t.construct, src, synth.added)
    diff = rules_diff(_rel(t, repo), t.construct.text, new, t.construct.crlf, synth, t.address)
    return diff.model_copy(update={"generator": "template:sg_ingress@1:cdk"})


def attr_diff(repo: Path, t: CdkTarget, fix: ConfigFix) -> tuple[Diff, list[str]]:
    """(diff, changes already met) for an attribute fix with CloudFormation paths: one
    property override per unmet change, judged on the synthesized resource."""
    ok, why = attr_applies(t.res, fix)
    if not ok:
        raise StageStop(
            "fix", f"the {fix.control} fix doesn't apply here: {why}", [_HAND], unknown=True
        )
    props: list[tuple[str, object]] = []
    changed, already = [], []
    for ch in fix.changes:
        present, v = _prop(t.res, ch.path)
        cur = _literal(t.res, ch, v) if present else None
        if present and ch.satisfied_by(cur):
            already.append(ch.describe())
            continue
        val: object = ch.value
        if ch.op == "includes":  # keep what the template already lists
            have = cur if isinstance(cur, list) else []
            val = [*have, *(x for x in ch.value if x not in have)]  # type: ignore[union-attr]
        props.append((ch.path, val))
        changed.append(ch.describe())
    if not changed:
        raise StageStop(
            "fix",
            f"the synthesized template already meets {fix.control}, so the live resource has "
            "drifted",
            ["deploy the app through your pipeline; the fix is already in the code"],
            why="PosturaNet fixes code, and this code is already fixed; the live resource isn't",
        )
    new = source.render_attr(t.construct, props, "Cfn" + t.res.type.rsplit("::", 1)[-1])
    summary = f"{t.construct.construct_id} " + "; ".join(changed)
    return _diff(repo, t, new, summary, "template:config_attribute@1:cdk"), already


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
    # an open CfnSecurityGroupIngress the edit removed; the group's other ingress must not change
    ours = owned_ingress(value(before.template.root)["Resources"], before.logical_id)
    removed = set(ours) - set(value(after.template.root)["Resources"])

    def rest(t: Template) -> Any:
        out = dict(value(t.root))
        out["Resources"] = {
            k: v
            for k, v in out["Resources"].items()
            if k != before.logical_id and k not in removed and v.get("Type") != "AWS::CDK::Metadata"
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
    checks.append(
        Check(id="changeset", required=False, result=CheckResult.SKIPPED, detail=CHANGESET_NOTE)
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


def validate_attr(
    t: CdkTarget,
    diff: Diff,
    fix: ConfigFix,
    config: Config,
    aws: ClientFactory | None,
    runner: CdkRunner | None,
    *,
    offline: bool,
) -> ValidationReport:
    want = {ch.path for ch in fix.changes}

    def check(c: Construct) -> Check:
        missing = sorted(want - set(source.overrides(c)) - set(_already(t, fix)))
        return _source_check(
            not missing,
            "edited source overrides the fix's properties",
            f"edited source has no override of {', '.join(missing)}",
        )

    return _validate(t, diff, config, aws, runner, offline, check, attr_checks(fix))


def _already(t: CdkTarget, fix: ConfigFix) -> list[str]:
    out = []
    for ch in fix.changes:
        present, v = _prop(t.res, ch.path)
        if present and ch.satisfied_by(_literal(t.res, ch, v)):
            out.append(ch.path)
    return out
