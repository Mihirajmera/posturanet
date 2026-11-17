"""Locate for CloudFormation: physical id → stack and logical id → template file:line → owners.

The stack mapping comes from `cloudformation:DescribeStackResources` (read-only) or, offline,
from an export of it (`cloudformation.stack_resources` or `--state`). The template is the one
file in the repo that defines that logical id with that type. Anything else stops with
UNKNOWN: a resource with no source line (a SAM-generated role, a console resource) is never
guessed at.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml.nodes import MappingNode, Node

from posturanet.aws.session import ClientFactory
from posturanet.cfn.params import NO_VALUE, Scope, Unresolved
from posturanet.cfn.template import (
    Template,
    TemplateError,
    find_templates,
    get,
    key_node,
    line_of,
    load,
    value,
)
from posturanet.errors import StageStop
from posturanet.locate.codeowners import find_codeowners, owners_for
from posturanet.models import Confidence, Config, Finding, Location

PREFIX = "cfn."
STACK_TYPES = ("AWS::CloudFormation::Stack", "AWS::Serverless::Application")
_MAX_DEPTH = 5


@dataclass
class CfnResource:
    stack: str
    logical_id: str
    type: str
    template: Template
    node: MappingNode
    line: int  # line of the logical id key
    scope: Scope = field(default_factory=Scope)  # parameters and conditions; empty = none known

    @property
    def address(self) -> str:
        return address(self.stack, self.logical_id)

    @property
    def properties(self) -> Node | None:
        return get(self.node, "Properties")


def address(stack: str, logical_id: str) -> str:
    """`cfn.<stack>.<LogicalId>`: stack names and logical ids can't contain dots."""
    return f"{PREFIX}{stack}.{logical_id}"


def split_address(addr: str) -> tuple[str, str] | None:
    if not addr.startswith(PREFIX):
        return None
    stack, _, logical = addr[len(PREFIX) :].partition(".")
    return (stack, logical) if stack and logical else None


def _stack_rows(path: Path) -> list[dict[str, Any]] | None:
    """Rows of a `describe-stack-resources` export, or None if `path` isn't one."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    rows = data.get("StackResources") if isinstance(data, dict) else None
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else None


def _has_tf(root: Path) -> bool:
    return any(".terraform" not in p.parts and ".git" not in p.parts for p in root.rglob("*.tf"))


def is_cloudformation(repo: Path, config: Config, state_path: Path | None = None) -> bool:
    """`iac: cloudformation`, or (auto) a stack-resources export, or templates and no .tf."""
    if config.iac != "auto":
        return config.iac == "cloudformation"
    if state_path is not None:
        return _stack_rows(state_path) is not None
    if config.cloudformation.stack_resources:
        return True
    return not _has_tf(repo / config.terraform.root) and bool(find_templates(repo))


def _rel(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def stack_row(
    ids: list[str],
    repo: Path,
    config: Config,
    state_path: Path | None,
    aws: ClientFactory | None,
) -> tuple[dict[str, Any], str, list[dict[str, Any]] | None]:
    """(the stack resource whose physical id is one of `ids`, where it came from, the export's
    rows or None when read live)."""
    export = state_path or (
        repo / config.cloudformation.stack_resources
        if config.cloudformation.stack_resources
        else None
    )
    if export is not None:
        rows = _stack_rows(export)
        if rows is None:
            raise StageStop(
                "locate",
                f"{_rel(export, repo)} is not a describe-stack-resources export",
                ["export it with `aws cloudformation describe-stack-resources --stack-name …`"],
            )
        label = _rel(export, repo)
        export_rows: list[dict[str, Any]] | None = rows
    elif aws is not None:
        cf = aws("cloudformation")
        rows = []
        for rid in ids:
            if any(r.get("PhysicalResourceId") in ids for r in rows):
                break
            try:
                rows += cf.describe_stack_resources(PhysicalResourceId=rid)["StackResources"]
            except Exception as exc:  # botocore ClientError; boto3 is only imported in aws/
                if "does not exist" in str(exc):
                    continue
                raise StageStop(
                    "locate", f"cloudformation:DescribeStackResources failed: {exc}"
                ) from exc
        label = "cloudformation:DescribeStackResources"
        export_rows = None
    else:
        raise StageStop(
            "locate",
            "mapping a resource to its CloudFormation stack needs AWS access, which a dry run "
            "does not use",
            [
                "set cloudformation.stack_resources to an export of "
                "`aws cloudformation describe-stack-resources` (never commit real exports)",
                "or drop --dry-run",
            ],
        )
    found = {
        (str(r.get("StackName")), str(r.get("LogicalResourceId"))): r
        for r in rows
        if r.get("PhysicalResourceId") in ids
    }
    if not found:
        steps = [
            "check that this resource is managed by CloudFormation",
            "if it was created in the console, codifying it comes in a later release",
        ]
        if any(r.get("ResourceType") in STACK_TYPES for r in rows):
            steps.insert(0, "add each nested stack's describe-stack-resources rows to the export")
        raise StageStop(
            "locate", f"{ids[0]} is not in any CloudFormation stack ({label})", steps, unknown=True
        )
    if len(found) > 1:
        raise StageStop(
            "locate",
            f"{ids[0]} matches {len(found)} stack resources: "
            + ", ".join(f"{s}/{lid}" for s, lid in sorted(found)),
            ["fix the duplicate export rows, then re-run"],
        )
    return next(iter(found.values())), label, export_rows


def resolve(
    repo: Path,
    config: Config,
    stack: str,
    logical_id: str,
    rtype: str | None = None,
    *,
    candidates: list[Template] | None = None,
) -> CfnResource | str:
    """The template resource for `stack/logical_id`, or why it can't be found."""
    mapped = config.cloudformation.templates.get(stack)
    if candidates is None and mapped:
        try:
            candidates = [load(repo / mapped)]
        except (OSError, TemplateError) as exc:
            return f"cloudformation.templates.{stack} ({mapped}): {exc}"
    elif candidates is None:
        candidates = find_templates(repo)
    hits = []
    for t in candidates:
        node = t.resources.get(logical_id)
        if node is None:
            continue
        found_type = str(value(get(node, "Type")))
        if rtype is None or found_type == rtype:
            hits.append((t, node, found_type))
    if not hits:
        sam = any(t.sam for t in candidates)
        why = f"{logical_id} ({rtype or 'any type'}) is not defined in any template in this repo"
        if sam:
            why += "; it may be generated by the SAM transform, which has no source line to edit"
        return why
    if len(hits) > 1:
        files = ", ".join(_rel(t.path, repo) for t, _, _ in hits)
        return (
            f"{logical_id} is defined in {len(hits)} templates ({files}); "
            f"set cloudformation.templates.{stack} to the one stack {stack} deploys"
        )
    t, node, found_type = hits[0]
    resources = get(t.root, "Resources")
    assert isinstance(resources, MappingNode)
    key = key_node(resources, logical_id)
    return CfnResource(stack, logical_id, found_type, t, node, line_of(key) if key else 1)


def _parent_row(
    row: dict[str, Any], rows: list[dict[str, Any]] | None, aws: ClientFactory | None
) -> dict[str, Any] | None:
    """The `AWS::CloudFormation::Stack` row that created `row`'s stack, when it's nested."""
    sid, name = row.get("StackId"), row.get("StackName")

    def is_parent(r: dict[str, Any]) -> bool:
        pid = str(r.get("PhysicalResourceId", ""))
        return r.get("ResourceType") in STACK_TYPES and (
            pid == sid or (bool(name) and f":stack/{name}/" in pid)
        )

    if rows is None:
        if not sid or aws is None:
            return None
        try:
            rows = aws("cloudformation").describe_stack_resources(PhysicalResourceId=sid)[
                "StackResources"
            ]
        except Exception as exc:  # botocore ClientError; boto3 is only imported in aws/
            if "does not exist" in str(exc):
                return None
            why = f"cloudformation:DescribeStackResources failed: {exc}"
            raise StageStop("locate", why) from exc
    return next((r for r in rows if is_parent(r)), None)


def _nested_template(parent: CfnResource, repo: Path) -> Template | str:
    """The local template a nested stack resource points at (`TemplateURL` or SAM `Location`)."""
    key = "TemplateURL" if parent.type == STACK_TYPES[0] else "Location"
    url = value(get(parent.properties, key))
    try:
        url, _ = parent.scope.resolve(url)
    except Unresolved as exc:
        return f"{parent.logical_id} {key}: {exc}"
    if not isinstance(url, str) or not url:
        return f"{parent.logical_id} {key} is not a template path in this repo"
    if "://" in url or url.startswith("s3:"):
        return f"{parent.logical_id} {key} is a URL, not a template in this repo"
    path = (parent.template.path.parent / url).resolve()
    if not path.is_relative_to(repo.resolve()):
        return f"{parent.logical_id} {key} points outside the repo"
    try:
        return load(path)
    except (OSError, TemplateError) as exc:
        return f"{parent.logical_id} {key} ({url}): {exc}"


def _passed(parent: CfnResource) -> tuple[dict[str, Any], set[str]] | str:
    """(parameter values the parent passes to the nested stack, names it passes but can't
    resolve). Offline only; live runs read the nested stack's own parameters."""
    raw = value(get(parent.properties, "Parameters"))
    if raw is None:
        return {}, set()
    if not isinstance(raw, dict) or "Ref" in raw or any(k.startswith("Fn::") for k in raw):
        return f"{parent.logical_id} Parameters is not a literal mapping"
    passed: dict[str, Any] = {}
    blocked: set[str] = set()
    for k, v in raw.items():
        try:
            r, _ = parent.scope.resolve(v)
        except Unresolved:
            blocked.add(k)
            continue
        if r is not NO_VALUE:
            passed[k] = r
    return passed, blocked


def _resolve_row(
    row: dict[str, Any],
    rows: list[dict[str, Any]] | None,
    repo: Path,
    config: Config,
    aws: ClientFactory | None,
    rtype: str | None,
    depth: int = 0,
) -> CfnResource | str:
    """`resolve` for a stack-resources row, following nested stacks up to their parent's
    `TemplateURL`, with the stack's parameters and the resource's `Condition` checked."""
    stack, logical = str(row["StackName"]), str(row["LogicalResourceId"])
    parent_row = None if stack in config.cloudformation.templates else _parent_row(row, rows, aws)
    if parent_row is None:
        res = resolve(repo, config, stack, logical, rtype)
        if isinstance(res, str):
            return res
        res.scope = Scope(res.template, stack, aws)
    else:
        if depth >= _MAX_DEPTH:
            return f"{stack} is nested more than {_MAX_DEPTH} stacks deep"
        parent = _resolve_row(parent_row, rows, repo, config, aws, None, depth + 1)
        if isinstance(parent, str):
            return f"nested stack {stack}: {parent}"
        if parent.type not in STACK_TYPES:
            return f"{parent.stack}/{parent.logical_id} is a {parent.type}, not a nested stack"
        t = _nested_template(parent, repo)
        passed = _passed(parent) if aws is None else ({}, set())  # live: its own params
        if isinstance(t, str) or isinstance(passed, str):
            return f"nested stack {stack}: {t if isinstance(t, str) else passed}"
        res = resolve(repo, config, stack, logical, rtype, candidates=[t])
        if isinstance(res, str):
            return res
        res.scope = Scope(t, stack, aws, *passed)
    cond = value(get(res.node, "Condition"))
    if cond is not None:
        on = res.scope.condition(str(cond))
        if on is None:
            return f"{logical} has Condition {cond}, which can't be resolved from known parameters"
        if not on:
            return (
                f"{logical} has Condition {cond}, which is false for stack {stack}'s "
                "parameters, so the template doesn't create it"
            )
    return res


def locate(
    finding: Finding,
    repo: Path,
    config: Config,
    state_path: Path | None,
    aws: ClientFactory | None,
    types: list[str],
) -> tuple[Location, CfnResource]:
    ids = [i for i in dict.fromkeys([finding.resource.id, finding.resource.arn]) if i]
    row, label, rows = stack_row(ids, repo, config, state_path, aws)
    stack, logical = str(row["StackName"]), str(row["LogicalResourceId"])
    rtype = str(row.get("ResourceType"))
    if rtype not in types:
        raise StageStop(
            "locate",
            f"{stack}/{logical} is a {rtype}, not {' or '.join(types)}",
            ["`posturanet fixes list` shows every control PosturaNet fixes"],
        )
    res = _resolve_row(row, rows, repo, config, aws, rtype)
    if isinstance(res, str):
        raise StageStop(
            "locate",
            res,
            [
                "pass the template path in .posturanet.yml: cloudformation.templates."
                f"{stack}: path/to/template.yaml",
                "fix this resource by hand if it has no template in this repo",
            ],
            unknown=True,
        )
    file_rel = _rel(res.template.path, repo)
    reasoning = [
        f"physical id matched in {label}: stack {stack}, logical id {logical}",
        f"defined in {file_rel}" + (" (SAM template)" if res.template.sam else ""),
    ]
    if get(res.template.root, "Parameters") is not None:
        reasoning.append(f"parameter values from {res.scope.source}")
    owners: list[str] = []
    codeowners = find_codeowners(repo)
    if codeowners is not None:
        owners = owners_for(codeowners, file_rel)
    reasoning.append(
        f"owners from {_rel(codeowners, repo)}"
        if owners and codeowners
        else "no CODEOWNERS rule matches this file"
    )
    loc = Location(
        address=res.address,
        file=file_rel,
        line=res.line,
        state_source=label,
        owners=owners,
        drift=None,
        confidence=Confidence.HIGH if owners else Confidence.MEDIUM,
        reasoning=reasoning,
    )
    return loc, res
