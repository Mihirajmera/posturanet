"""Locate for AWS CDK: physical id → stack and logical id → construct path → source line.

The stack mapping is the CloudFormation one (`cloudformation:DescribeStackResources` or its
export). The synthesized template's `aws:cdk:path` metadata names the construct; the source
line is the one constructor call in the app whose id is that literal string. Anything else
(no path metadata, an L1 `Cfn*` construct, a computed or repeated id) stops with UNKNOWN.

`cdk synth` runs with `--no-lookups` and with AWS credentials removed from its environment,
so it makes no AWS calls; it does run the customer's app, as their own CI does.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from posturanet.aws.session import ClientFactory
from posturanet.cdk import source
from posturanet.cdk.source import Construct
from posturanet.cfn.edit import BUCKET_TYPE, POLICY_TYPE, SG_TYPE
from posturanet.cfn.locate import CfnResource, stack_row
from posturanet.cfn.template import Template, TemplateError, get, key_node, line_of, load, value
from posturanet.errors import StageStop
from posturanet.locate.codeowners import find_codeowners, owners_for
from posturanet.models import Confidence, Config, Finding, Location

PREFIX = "cdk."
# L2 construct class for each resource type PosturaNet fixes.
CLASS_FOR = {SG_TYPE: "SecurityGroup", BUCKET_TYPE: "Bucket", POLICY_TYPE: "ManagedPolicy"}
_SKIP = {"node_modules", "cdk.out", ".git", ".venv", "venv"}
# Credentials and endpoints the CDK CLI could use to call AWS; region settings stay.
_STRIP = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
          "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
          "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
          "AWS_CONTAINER_AUTHORIZATION_TOKEN")  # fmt: skip


def address(stack: str, logical_id: str) -> str:
    return f"{PREFIX}{stack}.{logical_id}"


def split_address(addr: str) -> tuple[str, str] | None:
    if not addr.startswith(PREFIX):
        return None
    stack, _, logical = addr[len(PREFIX) :].partition(".")
    return (stack, logical) if stack and logical else None


# --- cdk synth


class CdkRunner(Protocol):
    def synth(self, app: Path, out: Path) -> str | None:
        """Synthesize the app in `app` into `out`. None on success, else what went wrong."""


class SubprocessCdk:
    def __init__(self, binary: str = "cdk", timeout_s: int = 300) -> None:
        self.binary = binary
        self.timeout_s = timeout_s

    def synth(self, app: Path, out: Path) -> str | None:
        exe = shutil.which(self.binary)
        if exe is None:
            return f"{self.binary} not found on PATH"
        nowhere = str(out / "no-aws-config")
        env = {k: v for k, v in os.environ.items() if k not in _STRIP}
        env |= {
            "AWS_SHARED_CREDENTIALS_FILE": nowhere,
            "AWS_CONFIG_FILE": nowhere,
            "AWS_EC2_METADATA_DISABLED": "true",
            "CDK_DISABLE_VERSION_CHECK": "1",
        }
        args = [exe, "synth", "--no-lookups", "--no-notices", "--quiet", "--output", str(out)]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed binary, list args
                args,
                cwd=app,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return f"timed out after {self.timeout_s}s"
        if proc.returncode == 0:
            return None
        lines = (proc.stderr or proc.stdout).strip().splitlines()
        return f"exit {proc.returncode}: {lines[-1] if lines else 'no output'}"


# --- the app and its cloud assembly


def _apps(repo: Path) -> list[Path]:
    return sorted(
        p.parent for p in repo.rglob("cdk.json") if not _SKIP & set(p.relative_to(repo).parts[:-1])
    )


def _has_tf(root: Path) -> bool:
    return any(".terraform" not in p.parts and ".git" not in p.parts for p in root.rglob("*.tf"))


def is_cdk(repo: Path, config: Config) -> bool:
    """`iac: cdk`, or (auto) a CDK app in the repo and no .tf files."""
    if config.iac != "auto":
        return config.iac == "cdk"
    found = config.cdk.app is not None or bool(_apps(repo))
    return found and not _has_tf(repo / config.terraform.root)


def app_dir(repo: Path, config: Config) -> Path:
    if config.cdk.app is not None:
        return repo / config.cdk.app
    apps = _apps(repo)
    if len(apps) != 1:
        raise StageStop(
            "locate",
            f"found {len(apps)} CDK apps (cdk.json files) in this repo",
            ["set cdk.app in .posturanet.yml to the directory of the app that deploys this stack"],
            unknown=True,
        )
    return apps[0]


@contextmanager
def assembly(
    repo: Path, config: Config, runner: CdkRunner | None, *, dry: bool
) -> Iterator[tuple[Path, str]]:
    """(cloud assembly directory, where it came from): `cdk.assembly`, or a fresh synth."""
    if config.cdk.assembly is not None:
        d = repo / config.cdk.assembly
        if not (d / "manifest.json").is_file():
            raise StageStop(
                "locate",
                f"cdk.assembly ({config.cdk.assembly}) has no manifest.json",
                ["point it at the output of `cdk synth -o <dir>`, or unset it"],
            )
        yield d, config.cdk.assembly
        return
    if dry:
        raise StageStop(
            "locate",
            "mapping a resource to its construct needs the synthesized app, and a dry run "
            "doesn't run cdk synth",
            [
                "set cdk.assembly to a cloud assembly your CI synthesized (`cdk synth -o …`)",
                "or drop --dry-run so PosturaNet runs `cdk synth --no-lookups` itself",
            ],
        )
    app = app_dir(repo, config)
    run = runner or SubprocessCdk(config.cdk.binary, config.validation.timeout_s)
    with tempfile.TemporaryDirectory(prefix="posturanet-cdk-") as tmp:
        err = run.synth(app, Path(tmp))
        if err is not None:
            raise StageStop(
                "locate",
                f"cdk synth failed: {err}",
                [
                    "run `cdk synth --no-lookups` in the app and fix what it reports",
                    "cached lookups belong in cdk.context.json",
                ],  # fmt: skip
            )
        yield Path(tmp), "cdk synth"


def stacks(d: Path) -> list[tuple[str, Path]]:
    """(deployed stack name, template) for every stack in the assembly, nested ones too."""
    try:
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[tuple[str, Path]] = []
    for aid, art in sorted((manifest.get("artifacts") or {}).items()):
        props = art.get("properties") or {}
        if art.get("type") == "aws:cloudformation:stack" and props.get("templateFile"):
            out.append((str(props.get("stackName") or aid), d / str(props["templateFile"])))
        elif art.get("type") == "cdk:cloud-assembly" and props.get("directoryName"):
            out += stacks(d / str(props["directoryName"]))
    return out


def stack_template(d: Path, label: str, stack: str) -> Template | str:
    paths = [p for name, p in stacks(d) if name == stack]
    if not paths:
        return f"stack {stack} is not in this CDK app's cloud assembly ({label})"
    if len(paths) > 1:
        return f"{len(paths)} stacks in the cloud assembly ({label}) are named {stack}"
    try:
        return load(paths[0])
    except (OSError, TemplateError) as exc:
        return f"the synthesized template for {stack} can't be read: {exc}"


@dataclass
class CdkTarget:
    res: CfnResource  # the resource in the synthesized template
    construct_path: str
    construct: Construct
    app: Path

    @property
    def address(self) -> str:
        return address(self.res.stack, self.res.logical_id)

    @property
    def original(self) -> str:
        return self.construct.on_disk(self.construct.text)


def in_template(t: Template, stack: str, logical: str) -> CfnResource | str:
    node = t.resources.get(logical)
    resources = get(t.root, "Resources")
    if node is None or resources is None:
        return f"{logical} is not in the synthesized {stack} template"
    key = key_node(resources, logical)  # type: ignore[arg-type]
    rtype = str(value(get(node, "Type")))
    return CfnResource(stack, logical, rtype, t, node, line_of(key) if key else 1)


def resolve(
    repo: Path, config: Config, d: Path, label: str, stack: str, logical: str
) -> CdkTarget | str:
    """The construct behind `stack/logical`, or why it can't be found with confidence."""
    t = stack_template(d, label, stack)
    if isinstance(t, str):
        return t
    res = in_template(t, stack, logical)
    if isinstance(res, str):
        return res
    meta = value(get(res.node, "Metadata"))
    path = meta.get("aws:cdk:path") if isinstance(meta, dict) else None
    if not isinstance(path, str):
        return f"{logical} has no aws:cdk:path metadata (path metadata is turned off in the app)"
    parts = path.split("/")
    cls = CLASS_FOR.get(res.type)
    if cls is None:
        return f"{logical} is a {res.type}; PosturaNet edits CDK code for {', '.join(CLASS_FOR)}"
    if len(parts) < 3 or parts[-1] != "Resource":
        return (
            f"{path} is not an L2 {cls} construct (L1 Cfn* constructs and resources other "
            "constructs generate aren't edited yet)"
        )
    app = app_dir(repo, config)
    try:
        hits = source.find(app, parts[-2], cls)
    except StageStop as exc:
        return f"can't read the app source to find '{parts[-2]}': {exc.reason}"
    if not hits:
        return (
            f"no {cls} construct with the literal id '{parts[-2]}' in the app source "
            f"(construct path {path}); the id may be computed"
        )
    if len(hits) > 1:
        where = ", ".join(f"{_rel(h.file, repo)}:{h.line}" for h in hits)
        return f"{len(hits)} {cls} constructs use the id '{parts[-2]}' ({where}); can't tell which"
    return CdkTarget(res, path, hits[0], app)


def _rel(path: Path, repo: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def locate(
    finding: Finding,
    repo: Path,
    config: Config,
    state_path: Path | None,
    aws: ClientFactory | None,
    types: list[str],
    runner: CdkRunner | None,
    *,
    dry: bool,
) -> tuple[Location, CdkTarget]:
    ids = [i for i in dict.fromkeys([finding.resource.id, finding.resource.arn]) if i]
    row, label = stack_row(ids, repo, config, state_path, aws)
    stack, logical = str(row["StackName"]), str(row["LogicalResourceId"])
    rtype = str(row.get("ResourceType"))
    if rtype not in types:
        raise StageStop(
            "locate",
            f"{stack}/{logical} is a {rtype}, not {' or '.join(types)}",
            ["`posturanet fixes list` shows every control PosturaNet fixes"],
        )
    with assembly(repo, config, runner, dry=dry) as (d, where):
        target = resolve(repo, config, d, where, stack, logical)
    if isinstance(target, str):
        raise StageStop(
            "locate",
            target,
            [
                "fix this resource by hand in the CDK app",
                "construct paths come from the aws:cdk:path metadata in the synthesized template",
            ],  # fmt: skip
            unknown=True,
        )
    c = target.construct
    file_rel = _rel(c.file, repo)
    lang = "TypeScript" if c.lang == "ts" else "Python"
    reasoning = [
        f"physical id matched in {label}: stack {stack}, logical id {logical}",
        f"construct {target.construct_path} (aws:cdk:path in {where})",
        f"defined in {file_rel}:{c.line} ({lang}, id '{c.construct_id}')",
    ]
    codeowners = find_codeowners(repo)
    owners = owners_for(codeowners, file_rel) if codeowners is not None else []
    reasoning.append(
        f"owners from {_rel(codeowners, repo)}"
        if owners and codeowners
        else "no CODEOWNERS rule matches this file"
    )
    loc = Location(
        address=target.address,
        file=file_rel,
        line=c.line,
        state_source=label,
        owners=owners,
        drift=None,
        confidence=Confidence.HIGH if owners else Confidence.MEDIUM,
        reasoning=reasoning,
    )
    return loc, target
