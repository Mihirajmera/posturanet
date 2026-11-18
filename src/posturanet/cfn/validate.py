"""Diffs and validation for CloudFormation fixes (FR-21..FR-26).

The template is validated statically: it parses, only the target resource changed, the edited
resource passes the control and the contract, and (with AWS access) the repo template still
matches what the stack deployed (`cloudformation:GetTemplate`, read-only) and, for security
groups, the live group's ingress (`ec2:DescribeSecurityGroups`) still matches the template.
`cfn-lint` runs when installed. A change set, CloudFormation's own preview, needs
`cloudformation:CreateChangeSet` (a write), so it runs only when the customer opts in
(`cloudformation.changeset_preview`): an UPDATE change set under its own role, never executed,
always deleted.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from posturanet.aws.changeset import NAME_PREFIX, ChangeSetClient
from posturanet.aws.session import ClientFactory
from posturanet.cfn.edit import (
    SG_TYPE,
    CfnPolicy,
    CfnSecurityGroup,
    attr_edit,
    attr_unmet,
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
from posturanet.configfix.catalog import ConfigFix
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
from posturanet.synth.sg_rules import Rule, norm_proto
from posturanet.synth.sg_z3 import Synthesis
from posturanet.validate.guardrails import check_paths
from posturanet.validate.invariants import MODEL_SCOPE, check_contract
from posturanet.validate.recheck import recheck as sg_recheck
from posturanet.validate.recheck import supported

CHANGESET_NOTE = "needs cloudformation:CreateChangeSet (a write); validated statically"
TEMPLATE_BODY_MAX = 51_200  # bytes; larger templates need TemplateURL, an S3 upload (a write)
_POLL_S = 2.0


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


def attr_diff(repo: Path, res: CfnResource, fix: ConfigFix) -> tuple[Diff, list[str]]:
    """(diff, changes already met) for an attribute fix with CloudFormation paths."""
    new, changed, already = attr_edit(res, fix)
    if not changed:
        raise StageStop(
            "fix",
            f"the template already meets {fix.control}, so the live resource has drifted",
            ["deploy the stack through your pipeline; the fix is already in the code"],
            why="PosturaNet fixes code, and this code is already fixed; the live resource isn't",
        )
    summary = f"{res.logical_id} " + "; ".join(changed)
    return _diff(repo, res, new, summary, "template:config_attribute@1:cloudformation"), already


def iam_diff(repo: Path, policy: CfnPolicy, changes: list[StatementChange]) -> Diff:
    new = iam_edit(policy, {c.statement.index: c.after for c in changes})
    removed = sorted({p for c in changes for p in c.removed})
    kept = sum(len(c.after) for c in changes)
    summary = f"{', '.join(removed)} → {kept} used action(s) in {len(changes)} statement(s)"
    diff = _diff(repo, policy.res, new, summary, "template:iam_least_privilege@1:cloudformation")
    return diff.model_copy(
        update={
            "target_address": policy.address,
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


def drift(res: CfnResource, aws: ClientFactory | None, offline: bool) -> Check:
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
    if res.type == SG_TYPE:
        return _live_sg(res, aws, check)
    return check(CheckResult.PASS, f"{res.logical_id} matches the template stack {res.stack} runs")


def _norm(r: Rule) -> Rule:
    # "-1" (all traffic) has no ports: AWS returns none, templates may write any.
    lo, hi = (-1, -1) if r.proto == "-1" else (r.from_port, r.to_port)
    return Rule(str(r.net), lo, hi, r.proto)


def _live_sg(
    res: CfnResource, aws: ClientFactory, check: Callable[[CheckResult, str], Check]
) -> Check:
    """Compare the live group's CIDR ingress with the template's, before the edit."""
    try:
        rows = aws("cloudformation").describe_stack_resources(
            StackName=res.stack, LogicalResourceId=res.logical_id
        )["StackResources"]
        group_id = next(
            r["PhysicalResourceId"]
            for r in rows
            if r.get("LogicalResourceId") == res.logical_id and r.get("PhysicalResourceId")
        )
        groups = aws("ec2").describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    except StopIteration:
        return check(
            CheckResult.ERROR, f"stack {res.stack} has no physical id for {res.logical_id}"
        )
    except Exception as exc:  # botocore ClientError; boto3 is only imported in aws/
        return check(CheckResult.ERROR, f"reading the live security group failed: {exc}")
    # shortcut: only CIDR sources are compared (as parse_sg models them); add group/prefix-list
    # sources when parse_sg reads SourceSecurityGroupId.
    live = {
        _norm(Rule(cidr, int(p.get("FromPort", -1)), int(p.get("ToPort", -1)), proto))
        for g in groups
        for p in g.get("IpPermissions", [])
        for proto in [norm_proto(p.get("IpProtocol", ""))]
        for cidr in [x["CidrIp"] for x in p.get("IpRanges", [])]
        + [x["CidrIpv6"] for x in p.get("Ipv6Ranges", [])]
    }
    try:
        planned = {_norm(r) for r in parse_sg(res).rules()}
    except StageStop as exc:
        return check(CheckResult.ERROR, exc.reason)
    if live != planned:
        extra, missing = len(live - planned), len(planned - live)
        return check(
            CheckResult.FAIL,
            f"live group {group_id} differs from {res.logical_id} in the template "
            f"({extra} rule(s) only live, {missing} only in the template); "
            "someone changed it outside CloudFormation. Reconcile it first",
        )
    return check(
        CheckResult.PASS,
        f"{res.logical_id} matches stack {res.stack}; live group {group_id} ingress matches",
    )


def _changeset(
    res: CfnResource,
    diff: Diff,
    config: Config,
    client: ChangeSetClient | None,
    offline: bool,
) -> Check:
    """Opt-in change-set preview; SKIPPED and not required unless the customer opted in."""
    if not config.cloudformation.changeset_preview.enabled:
        return Check(
            id="changeset", required=False, result=CheckResult.SKIPPED, detail=CHANGESET_NOTE
        )
    if offline:
        return Check(
            id="changeset",
            required=False,
            result=CheckResult.SKIPPED,
            detail="dry run: no change set created",
        )
    body = diff.files[0].new_content
    if len(body.encode("utf-8")) > TEMPLATE_BODY_MAX:
        return Check(
            id="changeset",
            required=False,
            result=CheckResult.SKIPPED,
            detail="template is over 51,200 bytes; a change set would need an S3 upload",
        )

    def check(result: CheckResult, detail: str) -> Check:
        return Check(id="changeset", required=True, result=result, detail=detail)

    if client is None:
        return check(CheckResult.ERROR, "changeset_preview is on but no change-set client is set")
    name = f"{NAME_PREFIX}{diff.sha256[:12]}"
    created = False
    try:
        stack = client.describe_stack(res.stack)
        status = str(stack.get("StackStatus", ""))
        if status.endswith("IN_PROGRESS"):
            return check(CheckResult.ERROR, f"stack {res.stack} is busy ({status}); retry later")
        _sweep(client, res.stack, name)
        client.create(
            res.stack,
            name,
            body,
            sorted(p["ParameterKey"] for p in stack.get("Parameters", [])),
            # Only what the stack already acknowledged; a fix needing more stops for a human.
            sorted(stack.get("Capabilities", [])),
        )
        created = True
        cs = _wait(client, res.stack, name, config.validation.timeout_s)
        result, detail = _judge(res, cs, _own_ingress(res, body))
    except Exception as exc:  # botocore errors; boto3 is only imported in aws/
        result, detail = CheckResult.ERROR, f"change set failed: {exc}"
    finally:
        if created:
            try:
                client.delete(res.stack, name)
            except Exception as exc:
                result = CheckResult.ERROR
                detail = f"{detail}; change set {name} was NOT deleted ({exc}): delete it by hand"
    return check(result, detail)


def _sweep(client: ChangeSetClient, stack: str, keep: str) -> None:
    """Delete PosturaNet change sets older than an hour (leftovers of crashed runs)."""
    now = client.clock()
    for cs in client.list_change_sets(stack):
        name = str(cs.get("ChangeSetName", ""))
        made = cs.get("CreationTime")
        if (
            name.startswith(NAME_PREFIX)
            and name != keep
            and made is not None
            and (now - made).total_seconds() > 3600
        ):
            client.delete(stack, name)


def _wait(client: ChangeSetClient, stack: str, name: str, timeout_s: int) -> dict[str, Any]:
    for _ in range(max(1, int(timeout_s / _POLL_S))):
        cs = client.describe(stack, name)
        if cs.get("Status") in ("CREATE_COMPLETE", "FAILED"):
            return cs
        client.sleep(_POLL_S)
    raise TimeoutError(f"change set not ready after {timeout_s}s")


def _own_ingress(res: CfnResource, body: str) -> set[str]:
    """A group's own SecurityGroupIngress resources, before and after the edit: the fix may
    modify, replace, add or remove them."""
    if res.type != SG_TYPE:
        return set()
    try:
        after = value(get(parse(body, res.template.path).root, "Resources"))
    except TemplateError:
        return set()
    before = value(get(res.template.root, "Resources"))
    return {
        lid
        for resources in (before, after)
        if isinstance(resources, dict)
        for lid in owned_ingress(resources, res.logical_id)
    }


def _judge(
    res: CfnResource, cs: dict[str, Any], own: set[str] | None = None
) -> tuple[CheckResult, str]:
    """PASS only for an in-place Modify of the target and, for a security group, changes to its
    own SecurityGroupIngress resources (each one rule; replacing one is how CloudFormation
    edits it). Anything else in the change set fails."""
    own = own or set()
    if cs.get("Status") == "FAILED":
        reason = str(cs.get("StatusReason", ""))
        if "didn't contain changes" in reason or "No updates" in reason:
            return CheckResult.FAIL, "the change set is empty; the edit changes nothing deployed"
        if "apabilit" in reason:
            return CheckResult.FAIL, (
                "the fix needs a CloudFormation capability the stack hasn't acknowledged; "
                "review it by hand"
            )
        return CheckResult.FAIL, f"CloudFormation rejected the change set: {reason}"
    changes = [
        c.get("ResourceChange", {}) for c in cs.get("Changes", []) if c.get("Type") == "Resource"
    ]
    ids = sorted(str(c.get("LogicalResourceId")) for c in changes)
    others = [i for i in ids if i != res.logical_id and i not in own]
    if others or not ids or ids.count(res.logical_id) > 1:
        return CheckResult.FAIL, f"the change set touches {len(ids)} resource(s): {', '.join(ids)}"
    rules = [c for c in changes if c.get("LogicalResourceId") in own]
    for c in rules:
        if c.get("Action") not in ("Add", "Modify", "Remove"):
            return CheckResult.FAIL, (
                f"CloudFormation would {c.get('Action')} {c.get('LogicalResourceId')}"
            )
    extra = f", plus {len(rules)} of its own ingress resource(s)" if rules else ""
    target = [c for c in changes if c.get("LogicalResourceId") == res.logical_id]
    if not target:  # only standalone ingress resources change; the group itself doesn't
        return (
            CheckResult.PASS,
            f"CloudFormation would change only {len(rules)} of {res.logical_id}'s "
            "ingress resource(s)",
        )
    change = target[0]
    if change.get("Action") != "Modify":
        return CheckResult.FAIL, f"CloudFormation would {change.get('Action')} {res.logical_id}"
    replacement = change.get("Replacement", "False")
    if replacement != "False":
        return CheckResult.FAIL, (
            f"CloudFormation would replace {res.logical_id} (Replacement: {replacement})"
        )
    return CheckResult.PASS, f"CloudFormation would modify only {res.logical_id}, in place{extra}"


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
    changeset: ChangeSetClient | None,
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
    checks.append(drift(res, aws, offline))
    checks.append(_changeset(res, diff, config, changeset, offline))
    checks.append(_cfn_lint(diff, config.validation.timeout_s))
    return ValidationReport(checks=checks)


Checks = Callable[[CfnResource], list[Check]]


def sg_checks(synth: Synthesis, contract: BehaviorContract, control: str) -> Checks:
    """Checks on the edited resource: rules as synthesized, contract holds, control passes."""
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

    return specific


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
    changeset: ChangeSetClient | None = None,
) -> ValidationReport:
    return _validate(
        res, diff, config, aws, offline, sg_checks(synth, contract, control), changeset
    )


def s3_checks(control: str) -> Checks:
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

    return specific


def validate_attr(
    res: CfnResource,
    diff: Diff,
    fix: ConfigFix,
    config: Config,
    aws: ClientFactory | None,
    *,
    offline: bool,
    changeset: ChangeSetClient | None = None,
) -> ValidationReport:
    def specific(edited: CfnResource) -> list[Check]:
        unmet = attr_unmet(edited, fix)
        return [
            Check(
                id="recheck",
                required=True,
                result=CheckResult.FAIL if unmet else CheckResult.PASS,
                detail="edited template still fails: " + "; ".join(unmet)
                if unmet
                else f"edited template meets {fix.control} ({len(fix.changes)} setting(s))",
            )
        ]

    return _validate(res, diff, config, aws, offline, specific, changeset)


def validate_s3(
    res: CfnResource,
    diff: Diff,
    control: str,
    config: Config,
    aws: ClientFactory | None,
    *,
    offline: bool,
    changeset: ChangeSetClient | None = None,
) -> ValidationReport:
    return _validate(res, diff, config, aws, offline, s3_checks(control), changeset)


def iam_checks(
    control: str,
    changes: list[StatementChange],
    usage: dict[str, ServiceUse],
    extra: list[str],
    name: str | None = None,
) -> Checks:
    bad = check_invariants(changes, usage, extra)

    def specific(edited: CfnResource) -> list[Check]:
        statements = parse_policy(edited, name).statements
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

    return specific


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
    changeset: ChangeSetClient | None = None,
    name: str | None = None,
) -> ValidationReport:
    checks = iam_checks(control, changes, usage, extra, name)
    return _validate(res, diff, config, aws, offline, checks, changeset)
