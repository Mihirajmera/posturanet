"""Locate for Pulumi: physical id → URN and resource name (offline, from a `pulumi stack export`)
→ the one constructor call in the program whose name argument is that string literal.

The export is read, never written, and never logged: state can hold secrets, and a secret
value reads as COMPUTED. No Pulumi CLI runs and no AWS call is made here. A resource inside a
component, a computed name, a name used by several calls or a provider other than AWS Classic
stops with UNKNOWN.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from posturanet.cdk import source as cdk_source
from posturanet.cdk.source import Construct
from posturanet.cfn.edit import BUCKET_TYPE, POLICY_TYPE, SG_TYPE
from posturanet.cfn.locate import CfnResource
from posturanet.errors import StageStop
from posturanet.locate.codeowners import find_codeowners, owners_for
from posturanet.models import Confidence, Config, Finding, Location
from posturanet.pulumi import component, model, yaml_source
from posturanet.pulumi.source import (
    LANGS,
    SUFFIX,
    Computed,
    InComponent,
    find,
    props,
    trusted,
)

PREFIX = "pulumi."
STACK = "pulumi:pulumi:Stack"
_SECRET_SIG = "4dabf18193072939515e22adb298388d"  # Pulumi's marker for a secret value
_NAME = re.compile(r"[\w.-]+")
_STACK = re.compile(r"[\w-]+")
_HAND = "fix this resource by hand in the Pulumi program"

# Pulumi type token -> (module, class) for the resources PosturaNet reads or edits.
SG = "aws:ec2/securityGroup:SecurityGroup"
SG_RULE = "aws:ec2/securityGroupRule:SecurityGroupRule"
SG_INGRESS = "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule"
BPA = "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock"
POLICY = "aws:iam/policy:Policy"
BUCKET_POLICY = "aws:s3/bucketPolicy:BucketPolicy"
CLASSES = {
    SG: ("ec2", "SecurityGroup"),
    SG_RULE: ("ec2", "SecurityGroupRule"),
    SG_INGRESS: ("vpc", "SecurityGroupIngressRule"),
    BPA: ("s3", "BucketPublicAccessBlock"),
    POLICY: ("iam", "Policy"),
}
# The CloudFormation type each fix's checks run on (pipeline passes these).
FOR_CFN = {SG_TYPE: SG, BUCKET_TYPE: BPA, POLICY_TYPE: POLICY}


def address(stack: str, name: str) -> str:
    return f"{PREFIX}{stack}.{name}"


def split_address(addr: str) -> tuple[str, str] | None:
    if not addr.startswith(PREFIX):
        return None
    stack, _, name = addr[len(PREFIX) :].partition(".")
    return (stack, name) if stack and name else None


# --- the program


def _projects(repo: Path) -> list[Path]:
    skip = {"node_modules", ".git", ".venv", "venv", ".pulumi"}
    return sorted(
        p.parent
        for p in [*repo.rglob("Pulumi.yaml"), *repo.rglob("Pulumi.yml")]
        if not skip & set(p.relative_to(repo).parts[:-1])
    )


def _has_tf(root: Path) -> bool:
    return any(".terraform" not in p.parts and ".git" not in p.parts for p in root.rglob("*.tf"))


def is_pulumi(repo: Path, config: Config) -> bool:
    """`iac: pulumi`, or (auto) a Pulumi.yaml in the repo and no .tf files."""
    if config.iac != "auto":
        return config.iac == "pulumi"
    found = config.pulumi.program is not None or bool(_projects(repo))
    return found and not _has_tf(repo / config.terraform.root)


@dataclass
class Program:
    root: Path  # holds Pulumi.yaml
    main: Path  # where the source is (`main:`)
    runtime: str  # nodejs | python | yaml

    def files(self) -> list[Path]:
        if self.runtime == "yaml":  # the resources are in Pulumi.yaml, or Main.yaml with `main:`
            names = [self.root / "Pulumi.yaml", self.root / "Pulumi.yml", self.main / "Main.yaml"]
            return [p for p in dict.fromkeys(names) if p.is_file()]
        suffix = SUFFIX[self.runtime]
        if suffix in (".go", ".cs", ".java"):
            skip = {
                "vendor",
                ".git",
                "testdata",
                ".pulumi",
                "bin",
                "obj",
                "build",
                "target",
                "test",
            }
            return [
                p
                for p in sorted(self.main.rglob(f"*{suffix}"))
                if p.is_file() and not p.name.endswith("_test.go")
                and not skip & set(p.relative_to(self.main).parts[:-1])
            ]  # fmt: skip
        return [p for p in cdk_source.source_files(self.main) if p.suffix == suffix]


def program(repo: Path, config: Config) -> Program:
    if config.pulumi.program is not None:
        root = repo / config.pulumi.program
    else:
        found = _projects(repo)
        if len(found) != 1:
            raise StageStop(
                "locate",
                f"found {len(found)} Pulumi projects (Pulumi.yaml files) in this repo",
                ["set pulumi.program in .posturanet.yml to the directory of the project"],
                unknown=True,
            )
        root = found[0]
    spec = root / "Pulumi.yaml" if (root / "Pulumi.yaml").is_file() else root / "Pulumi.yml"
    try:
        doc = YAML(typ="safe").load(spec.read_text(encoding="utf-8"))
    except (OSError, YAMLError) as exc:
        raise StageStop(
            "locate", f"can't read {spec.name} in {root.name}: {exc}", [_HAND], unknown=True
        ) from exc
    runtime = doc.get("runtime") if isinstance(doc, dict) else None
    if isinstance(runtime, dict):
        runtime = runtime.get("name")
    if runtime not in (*SUFFIX, "yaml"):
        raise StageStop(
            "locate",
            f"the Pulumi runtime is {runtime!r}; PosturaNet reads TypeScript (nodejs), Python, "
            "Go, C# (dotnet), Java and YAML",
            [_HAND],
            unknown=True,
        )
    main = doc.get("main") if isinstance(doc, dict) else None
    base = root / main if isinstance(main, str) else root
    return Program(root, base if base.is_dir() else root, str(runtime))


# --- the stack export


@dataclass
class StateResource:
    urn: str
    type: str
    name: str
    stack: str
    id: str | None
    inputs: dict[str, Any]
    outputs: dict[str, Any]
    parent_type: str | None
    parent: str | None = None  # the parent's URN


def _unsecret(v: Any) -> Any:
    if isinstance(v, dict):
        if _SECRET_SIG in v:
            return Computed("[secret]")
        return {k: _unsecret(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_unsecret(x) for x in v]
    return v


@dataclass
class Export:
    label: str
    resources: list[StateResource] = field(default_factory=list)

    def by_urn(self, urn: str) -> StateResource | None:
        return next((r for r in self.resources if r.urn == urn), None)

    def of_type(self, rtype: str) -> list[StateResource]:
        return [r for r in self.resources if r.type == rtype]


def _parse_urn(urn: str) -> tuple[str, str, str] | None:
    """(stack, qualified type, name) of `urn:pulumi:<stack>::<project>::<type>::<name>`."""
    m = re.fullmatch(r"urn:pulumi:([^:]+)::[^:]+::(.+)::([^:]*)", urn)
    return (m.group(1), m.group(2), m.group(3)) if m else None


def _export_path(repo: Path, config: Config, state_path: Path | None) -> Path | None:
    if config.pulumi.stack_export is not None:
        return repo / config.pulumi.stack_export
    return state_path


def load_export(repo: Path, config: Config, state_path: Path | None) -> Export:
    path = _export_path(repo, config, state_path)
    steps = [
        "run `pulumi stack export --file stack.json` for the deployed stack and set "
        "pulumi.stack_export in .posturanet.yml (keep it out of git: state can hold secrets)",
    ]
    if path is None:
        raise StageStop(
            "locate", "mapping a resource to its Pulumi URN needs a stack export", steps
        )
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        rows = doc["deployment"]["resources"]
        if not isinstance(rows, list):
            raise TypeError("resources is not a list")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise StageStop(
            "locate", f"the stack export {path.name} can't be read ({type(exc).__name__})", steps
        ) from exc
    out = Export(path.name)
    for r in rows:
        urn = r.get("urn") if isinstance(r, dict) else None
        parsed = _parse_urn(urn) if isinstance(urn, str) else None
        if parsed is None or r.get("delete") or r.get("pendingReplacement"):
            continue
        stack, qualified, name = parsed
        parent = _parse_urn(str(r.get("parent") or ""))
        rid = r.get("id")
        out.resources.append(
            StateResource(
                str(urn),
                str(r.get("type") or qualified.rsplit("$", 1)[-1]),
                name,
                stack,
                rid if isinstance(rid, str) and rid else None,
                _unsecret(r.get("inputs") or {}),
                _unsecret(r.get("outputs") or {}),
                parent[1] if parent else None,
                str(r.get("parent")) if parent else None,
            )
        )
    return out


def _matches(r: StateResource, ids: list[str]) -> bool:
    arn = r.outputs.get("arn")
    return r.id in ids or (isinstance(arn, str) and arn in ids)


def find_state(exp: Export, ids: list[str], types: list[str]) -> StateResource:
    """The one resource of `types` the finding names; for S3, the bucket's public access block."""
    want = [FOR_CFN.get(t, t) for t in types]
    if BPA in want:
        hits = [
            r
            for r in exp.of_type(BPA)
            if r.inputs.get("bucket") in ids or r.outputs.get("bucket") in ids
        ]
        if not hits and any(_matches(r, ids) for r in exp.resources):
            raise StageStop(
                "locate",
                f"the bucket has no aws.s3.BucketPublicAccessBlock in {exp.label}; PosturaNet "
                "edits existing literals and won't add a resource",
                [
                    "add an aws.s3.BucketPublicAccessBlock for the bucket by hand, "
                    "or re-run once it exists",
                ],
                unknown=True,
            )
    else:
        hits = [r for r in exp.resources if _matches(r, ids)]
    if not hits:
        raise StageStop(
            "locate",
            f"{ids[0]} is not in the stack export {exp.label}",
            [
                "export the stack that deploys this resource (`pulumi stack export`)",
                "a resource created outside Pulumi has no program line to change",
            ],
            unknown=True,
        )
    if len(hits) > 1:
        names = ", ".join(sorted(r.name for r in hits))
        raise StageStop(
            "locate", f"{len(hits)} resources in {exp.label} match ({names})", [_HAND], unknown=True
        )
    r = hits[0]
    if r.type not in want:
        raise StageStop(
            "locate",
            f"{r.name} is a {r.type}, not {' or '.join(want)}",
            ["`posturanet fixes list` shows every control PosturaNet fixes"],
        )
    return r


# --- the target


@dataclass
class Part:
    """One resource in the program: the target, or a standalone ingress rule of the target."""

    state: StateResource
    construct: Construct


@dataclass
class PulumiTarget:
    state: StateResource
    construct: Construct
    program: Path
    label: str  # the export's file name
    rules: list[Part] = field(default_factory=list)  # standalone ingress (security groups)
    files: list[Path] = field(default_factory=list)  # the program's source files
    res: CfnResource = field(init=False)

    def __post_init__(self) -> None:
        self.res = model.resource(
            self.state.type, self.view(), self.state.stack, self.state.name, self.construct
        )

    @property
    def address(self) -> str:
        return address(self.state.stack, self.state.name)

    @property
    def original(self) -> str:
        return self.construct.on_disk(self.construct.text)

    def original_of(self, path: Path) -> str:
        """A file the diff edits, as it is on disk now."""
        c = next(p.construct for p in self.parts() if p.construct.file == path)
        return c.on_disk(c.text)

    def parts(self) -> list[Part]:
        return [Part(self.state, self.construct), *self.rules]

    def view(self, texts: dict[Path, str] | None = None) -> model.View:
        """The source literals the checks read, from the files as they are (or `texts`)."""
        return model.read(self.state.type, self.parts(), texts or {})


def _construct(prog: Program, r: StateResource, repo: Path, exp: Export) -> Construct | str:
    cls = CLASSES.get(r.type)
    if cls is None:
        return f"{r.name} is a {r.type}; PosturaNet edits Pulumi code for {', '.join(CLASSES)}"
    if "$" in r.urn.split("::")[2] or (r.parent_type and r.parent_type != STACK):
        return _in_component(prog, r, repo, exp, cls)
    if not _NAME.fullmatch(r.name) or not _STACK.fullmatch(r.stack):
        return f"the URN {r.urn} has characters PosturaNet doesn't put in file names"
    yaml = prog.runtime == "yaml"
    try:
        hits = (
            yaml_source.find(prog.files(), r.name, r.type)
            if yaml
            else find(prog.files(), r.name, cls[1], cls[0])
        )
    except StageStop as exc:
        return f"can't read the program source to find '{r.name}': {exc.reason}"
    if not hits:
        what = f"{yaml_source.short(r.type)} resource" if yaml else f"{cls[0]}.{cls[1]} call"
        return (
            f"no {what} with the literal name '{r.name}' in the program source; the name may "
            "be computed"
        )
    if len(hits) > 1:
        where = ", ".join(f"{_rel(h.file, repo)}:{h.line}" for h in hits)
        what = "resources" if yaml else f"{cls[1]} calls"
        return f"{len(hits)} {what} use the name '{r.name}' ({where}); can't tell which"
    if props(hits[0]).computed:
        return f"the arguments of '{r.name}' are not a literal object; PosturaNet won't guess"
    return hits[0]


def _in_component(
    prog: Program, r: StateResource, repo: Path, exp: Export, cls: tuple[str, str]
) -> Construct | str:
    """The call inside a component used exactly once (see `component.py`), or why not."""
    comp_type = r.parent_type or "resource"
    why = f"{r.name} is created inside the component {comp_type}"
    parent = exp.by_urn(r.parent or "")
    if parent is None or parent.parent_type != STACK or r.urn.split("::")[2].count("$") != 1:
        return f"{why}, which is not directly under the stack; PosturaNet traces one level only"
    if prog.runtime == "yaml":
        return f"{why}; a YAML program can't define a component, so its code isn't here"
    instances = len(exp.of_type(parent.type))
    if instances != 1:
        return f"{why}, which the stack export has {instances} times; an edit would change all"
    comps = component.find(prog.files(), parent.type)
    if len(comps) != 1:
        return (
            f"{why}; {len(comps)} classes or functions in the program register {parent.type}, "
            "so PosturaNet can't tell which code made it"
        )
    comp = comps[0]
    used = component.uses(prog.files(), comp)
    if used != 1:
        return f"{why}; {comp.name} is instantiated {used} times in the program, not once"
    text = comp.file.read_bytes().decode("utf-8", errors="replace")
    hit = component.pick(component.children(comp, text, cls[1], cls[0], parent.type), r.name)
    if isinstance(hit, str):
        return f"{why} ({comp.name}, {_rel(comp.file, repo)}:{comp.line}): {hit}"
    if props(hit).computed:
        return f"the arguments of '{r.name}' in {comp.name} are not a literal object"
    return hit


def _standalone(exp: Export, sg: StateResource) -> list[StateResource]:
    """Standalone ingress resources on the group. One whose group can't be read stops."""
    out = []
    for r in [*exp.of_type(SG_RULE), *exp.of_type(SG_INGRESS)]:
        gid = r.inputs.get("securityGroupId")
        if r.type == SG_RULE and r.inputs.get("type") == "egress":
            continue
        if isinstance(gid, Computed) or not isinstance(gid, str):
            raise StageStop(
                "locate",
                f"{r.name} ({r.type}) has a security group id PosturaNet can't read, so it "
                f"may add rules to {sg.name}",
                [_HAND],
                unknown=True,
            )
        if gid == sg.id:
            out.append(r)
    return sorted(out, key=lambda r: r.name)


def resolve(repo: Path, config: Config, exp: Export, state: StateResource) -> PulumiTarget | str:
    """The program code behind `state`, or why it can't be found with confidence."""
    prog = program(repo, config)
    c = _construct(prog, state, repo, exp)
    if isinstance(c, str):
        return c
    rules = []
    if state.type == SG:
        try:
            standalone = _standalone(exp, state)
        except StageStop as exc:
            return exc.reason
        for r in standalone:
            rc = _construct(prog, r, repo, exp)
            if isinstance(rc, str):
                return f"ingress rule {r.name}: {rc}"
            rules.append(Part(r, rc))
        unowned = _rule_calls(prog, exp, c, {r.state.name for r in rules})
        if unowned is not None:
            return unowned
    try:
        return PulumiTarget(state, c, prog.main, exp.label, rules, prog.files())
    except StageStop as exc:
        return exc.reason


def _rule_calls(prog: Program, exp: Export, sg: Construct, ours: set[str]) -> str | None:
    """Every standalone ingress call in the program must be deployed (in the export) and point
    at this group exactly when the export says it does; a rule written since the last deploy
    could open the group without PosturaNet seeing it."""
    known = {r.name for r in [*exp.of_type(SG_RULE), *exp.of_type(SG_INGRESS)]}
    yaml = prog.runtime == "yaml"
    form = {"yaml": "${{{}.id}}", "go": "{}.ID()", "cs": "{}.Id", "java": "{}.id()"}.get(
        sg.lang, "{}.id"
    )
    here = form.format(sg.var) if sg.var else None
    try:
        refs = list(_yaml_rule_refs(prog.files()) if yaml else _rule_refs(prog.files()))
    except StageStop as exc:
        return exc.reason
    for fname, name, ref in refs:
        if name is None or name not in known:
            what = f"'{name}' in {fname} is not in the stack export" if name else (
                f"in {fname} has a computed name")  # fmt: skip
            return (
                f"ingress rule {what}, so it may change '{sg.construct_id}' in ways the "
                "deployed state doesn't show"
            )
        if (ref is not None and ref == here) != (name in ours):
            return (
                f"ingress rule '{name}' points at a different group in the program "
                "than in the stack export"
            )
    return None


def _rule_refs(files: list[Path]) -> Iterator[tuple[str, str | None, str | None]]:
    """(file name, literal name, group reference) of every standalone ingress call."""
    for module, cls in (CLASSES[SG_RULE], CLASSES[SG_INGRESS]):
        for f, text, masked, m in _calls(files, module, cls):
            o = m.end() - 1
            args = cdk_source.items(masked, o, cdk_source.close_of(masked, o))
            at = 1 if f.suffix == ".go" else 0  # Go: New…(ctx, "name", …)
            lit = cdk_source.str_lit(text, args[at]) if len(args) > at else None
            ref = re.search(
                r"(?:securityGroupId\s*[:(]|security_group_id\s*=|SecurityGroupId\s*[:=])\s*"
                r"([\w.]+(?:\(\))?)\s*[,)}\n]",
                masked[o : cdk_source.close_of(masked, o)],
            )
            yield f.name, lit[0] if lit else None, ref.group(1) if ref else None


def _yaml_rule_refs(files: list[Path]) -> Iterator[tuple[str, str | None, str | None]]:
    """The same for YAML; a resource whose type isn't a literal may be a rule, so it counts."""
    for f in files:
        text = f.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
        for r in yaml_source.resources(f, text):
            if r.type is not None and not any(
                yaml_source.is_type(r, t) for t in (SG_RULE, SG_INGRESS)
            ):
                continue
            p = r.node.get("properties")
            gid = p.get("securityGroupId") if p is not None else None
            ref = gid.value.strip() if gid is not None and gid.kind == "scalar" else None
            yield f.name, r.name if r.type is not None else None, ref


def _calls(
    files: list[Path], module: str, cls: str
) -> Iterator[tuple[Path, str, str, re.Match[str]]]:
    """(file, LF text, masked text, match) for every `<…module.>cls(` call in `files`."""
    for f in files:
        text = f.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
        lang = LANGS[f.suffix]
        masked = cdk_source.mask(text, lang)
        for m in cdk_source._call_re("New" + cls if lang == "go" else cls, lang).finditer(masked):
            if trusted(lang, m.group(1), masked, module, cls):
                yield f, text, masked, m


def resolve_address(repo: Path, config: Config, addr: str, exp: Export) -> PulumiTarget | str:
    parts = split_address(addr)
    assert parts is not None
    hits = [r for r in exp.resources if (r.stack, r.name) == parts and r.type in (SG, BPA, POLICY)]
    if len(hits) != 1:
        return f"{addr} is {'not' if not hits else 'ambiguous'} in the stack export {exp.label}"
    return resolve(repo, config, exp, hits[0])


def _rel(path: Path, repo: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def locate(
    finding: Finding,
    repo: Path,
    config: Config,
    state_path: Path | None,
    types: list[str],
) -> tuple[Location, PulumiTarget]:
    ids = [i for i in dict.fromkeys([finding.resource.id, finding.resource.arn]) if i]
    exp = load_export(repo, config, state_path)
    state = find_state(exp, ids, types)
    target = resolve(repo, config, exp, state)
    if isinstance(target, str):
        raise StageStop(
            "locate",
            target,
            [_HAND, "the URN and name come from the stack export; the line from the program"],
            unknown=True,
        )
    explained = model.explains(state.type, target.view(), target.parts())
    if explained is not None:
        raise StageStop(
            "locate",
            explained,
            [
                "values from variables, loops, other files or `pulumi config` aren't edited; "
                + _HAND,
                "if the program changed since the last deploy, run `pulumi up` first",
            ],
            unknown=True,
        )
    drifted = model.drift(state.type, target.parts())
    if drifted is not None:
        raise StageStop(
            "locate",
            f"drift: {drifted}",
            ["run `pulumi refresh` and `pulumi up` through your pipeline, export again, re-run"],
        )
    c = target.construct
    file_rel = _rel(c.file, repo)
    lang = {
        "ts": "TypeScript",
        "py": "Python",
        "yaml": "YAML",
        "go": "Go",
        "cs": "C#",
        "java": "Java",
    }[c.lang]
    reasoning = [
        f"physical id matched in {exp.label}: {state.urn}",
        f"defined in {file_rel}:{c.line} ({lang}, name '{state.name}')",
        *(
            [
                f"inside component {c.component}, defined and instantiated once in the program; "
                "the edit is to the component's code"
            ]
            if isinstance(c, InComponent)
            else []
        ),  # fmt: skip
        *(
            f"ingress rule {p.state.name} in {_rel(p.construct.file, repo)}:{p.construct.line}"
            for p in target.rules
        ),
        "the literals match the stack export's inputs and outputs",
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
        state_source=exp.label,
        owners=owners,
        drift=False,
        confidence=Confidence.HIGH if owners else Confidence.MEDIUM,
        reasoning=reasoning,
    )
    return loc, target


def bucket_policies(t: PulumiTarget) -> bool:
    """Whether the program defines any aws.s3.BucketPolicy (not judged on Pulumi yet)."""
    if t.construct.lang == "yaml":
        return any(
            r.type is None or yaml_source.is_type(r, BUCKET_POLICY)
            for f in t.files
            for r in yaml_source.resources(f, f.read_text(encoding="utf-8"))
        )
    return any(True for _ in _calls(t.files, "s3", "BucketPolicy"))
