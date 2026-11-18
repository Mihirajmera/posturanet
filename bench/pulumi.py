"""Pulumi benchmark: the same three fix types (open security group, public bucket, wildcard IAM
policy) when the source is a Pulumi program (TypeScript or Python, AWS Classic provider).

Every case runs the real pipeline (`run_fix`, check mode) on a copy of
`tests/fixtures/pulumi/ts-program` or `py-program`, with the program or the stack export
changed to set a trap: a computed value in the field the fix edits, a resource inside a
component, a name used twice, an ingress rule written since the last deploy, a program that no
longer matches the export, and drift between the export's inputs and outputs. No AWS call is
made. A fix is scored on the edited program's literals, read back through the stack export.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

ROOT = Path(__file__).resolve().parent.parent

from bench.cases import END  # noqa: E402
from bench.cfn import FAMILY, score  # noqa: E402
from bench.common import Expect, Result, per_case, summary  # noqa: E402
from posturanet import pulumi  # noqa: E402
from posturanet.evidence import FileSource  # noqa: E402
from posturanet.models.config import load_config  # noqa: E402
from posturanet.pipeline import Context, run_fix  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
Family = Literal["sg", "s3", "iam"]
Export = dict[str, Any]


def _res(doc: Export, name: str) -> dict[str, Any]:
    return next(r for r in doc["deployment"]["resources"] if r["urn"].endswith(f"::{name}"))


def _component(doc: Export) -> None:
    sg = _res(doc, "bastion-sg")
    stack = sg["parent"]
    comp = stack.replace("pulumi:pulumi:Stack::acme-infra-prod", "acme:net:Bastion::bastion")
    doc["deployment"]["resources"].append({"urn": comp, "type": "acme:net:Bastion"})
    sg["urn"] = sg["urn"].replace("::aws:ec2/", "::acme:net:Bastion$aws:ec2/")
    sg["parent"] = comp


def _sg_drift(doc: Export) -> None:
    _res(doc, "bastion-sg")["outputs"]["ingress"].append(
        {"protocol": "tcp", "fromPort": 3389, "toPort": 3389, "cidrBlocks": ["198.51.100.0/24"]}
    )


def _no_block(doc: Export) -> None:
    doc["deployment"]["resources"].remove(_res(doc, "assets-pab"))


def _wider_policy(doc: Export) -> None:
    r = _res(doc, "app")
    for side in ("inputs", "outputs"):
        p = json.loads(r[side]["policy"])
        p["Statement"][0]["Action"].append("s3:*")
        r[side]["policy"] = json.dumps(p)


@dataclass
class PulumiCase:
    id: str
    family: Family
    lang: Literal["ts", "py"]
    title: str
    why: str
    expect: Expect
    edits: dict[str, tuple[str, str]] = field(default_factory=dict)  # file -> (old, new)
    export: Callable[[Export], None] | None = None
    exit_code: int = 0
    says: str = ""


NET, STORE, MAIN = "infra/network.ts", "infra/storage.ts", "__main__.py"
RDP = (
    '\nnew aws.vpc.SecurityGroupIngressRule("bastion-rdp", {\n'
    "    securityGroupId: bastionSg.id,\n"
    '    ipProtocol: "tcp",\n    fromPort: 3389,\n    toPort: 3389,\n'
    '    cidrIpv4: "0.0.0.0/0",\n});\n'
)

CASES: list[PulumiCase] = [
    PulumiCase("pulumi-sg-ts", "sg", "ts", "Bastion SSH open, inline ingress (TypeScript)",
               "Literal `ingress` objects on the group; the open one becomes one object per "
               "observed source.", "fix"),
    PulumiCase("pulumi-sg-py-standalone", "sg", "py",
               "Bastion SSH open through an aws.ec2.SecurityGroupRule (Python)",
               "The open rule is its own resource; its `cidr_blocks` list is narrowed in place.",
               "fix"),
    PulumiCase("pulumi-sg-computed-cidr", "sg", "ts", "SSH rule's CIDR is a variable",
               "`cidrBlocks: [adminCidr]`; its value isn't a literal in the program.", "stop",
               {NET: ('cidrBlocks: ["0.0.0.0/0"]', "cidrBlocks: [adminCidr]")}, exit_code=3,
               says="not a literal"),
    PulumiCase("pulumi-sg-component", "sg", "ts", "Group created inside a component resource",
               "The URN's parent is a component; the name in the program may be computed.",
               "stop", export=_component, exit_code=3, says="inside the component"),
    PulumiCase("pulumi-sg-duplicate-name", "sg", "ts", "Two SecurityGroup calls named bastion-sg",
               "PosturaNet won't pick one of two constructor calls.", "stop",
               {STORE: ("\nnew aws.iam.Policy(", '\nnew aws.ec2.SecurityGroup("bastion-sg", '
                        '{ description: "dev" });\n\nnew aws.iam.Policy(')},
               exit_code=3, says="calls use the name"),
    PulumiCase("pulumi-sg-undeployed-rule", "sg", "ts", "RDP rule written but not deployed",
               "A new SecurityGroupIngressRule on the group isn't in the stack export; a fix "
               "from the export would miss it.", "stop",
               {NET: ("\nexport const", RDP + "\nexport const")}, exit_code=3,
               says="not in the stack export"),
    PulumiCase("pulumi-sg-drift", "sg", "ts", "RDP rule added to the live group by hand",
               "The export's outputs (after a refresh) show 3389 from 198.51.100.0/24 that no "
               "input declares; editing the program would hide it.", "stop", export=_sg_drift,
               exit_code=3, says="drift"),
    PulumiCase("pulumi-s3-ts", "s3", "ts", "Public bucket, BucketPublicAccessBlock (TypeScript)",
               "One flag set to false, two missing; all four become true.", "fix"),
    PulumiCase("pulumi-s3-py", "s3", "py", "Public bucket, BucketPublicAccessBlock (Python)",
               "Keyword arguments; the missing flags are added in the call's layout.", "fix"),
    PulumiCase("pulumi-s3-no-block", "s3", "ts", "Bucket with no BucketPublicAccessBlock",
               "The fix needs a new resource; PosturaNet edits existing literals only.", "stop",
               export=_no_block, exit_code=3, says="no aws.s3.BucketPublicAccessBlock"),
    PulumiCase("pulumi-s3-computed-flag", "s3", "ts", "blockPublicAcls comes from config",
               "One flag is `cfg.requireBoolean(...)`; PosturaNet can't tell what it is.",
               "stop", {STORE: ("blockPublicAcls: false", 'blockPublicAcls: cfg.requireBoolean'
                                '("block")')}, exit_code=3, says="not a literal boolean"),
    PulumiCase("pulumi-iam-ts", "iam", "ts", "ec2:* and logs:* in JSON.stringify (TypeScript)",
               "The Action array is narrowed in its multi-line layout.", "fix"),
    PulumiCase("pulumi-iam-py", "iam", "py", "ec2:* and logs:* in json.dumps (Python)",
               "The Action list is narrowed inline.", "fix"),
    PulumiCase("pulumi-iam-variable-policy", "iam", "ts", "Policy document is a variable",
               "`policy: appPolicy`; the document isn't written in the call.", "stop",
               {STORE: ("policy: JSON.stringify({", "policy: appPolicy,\n    _old: ({")},
               exit_code=3, says="not a literal document"),
    PulumiCase("pulumi-iam-program-differs", "iam", "ts", "Deployed policy also allows s3:*",
               "The stack runs a wider document than the program; a fix from the program "
               "would be wrong.", "stop", export=_wider_policy, exit_code=3,
               says="differs from the stack export"),
]  # fmt: skip


def _repo(case: PulumiCase, work: Path) -> Path:
    repo = work / "repo"
    shutil.copytree(FIX / "pulumi" / f"{case.lang}-program", repo)
    for rel, (old, new) in case.edits.items():
        path = repo / rel
        text = path.read_text(encoding="utf-8")
        assert old in text, (case.id, old)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
    if case.export is not None:
        path = repo / "stack-export.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        case.export(doc)
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return repo


def posturanet(case: PulumiCase, work: Path) -> tuple[Result, int]:
    repo = _repo(case, work)
    config, _ = load_config(repo)
    finding, evidence, *_ = FAMILY[case.family]
    ctx = Context(mode="check", evidence=FileSource(FIX / evidence), clock=lambda: END)
    record = run_fix(str(FIX / "findings" / finding), repo, config, ctx)
    if record.result != "VALIDATED" or record.diff is None or record.location is None:
        stop = next((s for s in record.stages if s.status.value in ("fail", "unknown")), None)
        why = f"{stop.name} {stop.status.value}: {stop.summary}" if stop else record.result
        return Result("PosturaNet", "STOPPED", case.expect, note=why), record.exit_code
    for f in record.diff.files:
        (repo / f.path).write_bytes(f.new_content.encode("utf-8"))
    target = pulumi.resolve_address(
        repo, config, record.location.address, pulumi.load_export(repo, config, None)
    )
    assert not isinstance(target, str), target
    return score(case.family, case.expect, target.res, record.result_detail or ""), 0


def run_case(case: PulumiCase) -> tuple[Result, int]:
    with tempfile.TemporaryDirectory() as tmp:
        return posturanet(case, Path(tmp))


def run() -> dict[str, list[Result]]:
    return {c.id: [run_case(c)[0]] for c in CASES}


def wrongly_safe(results: dict[str, list[Result]]) -> list[str]:
    return [
        cid
        for cid, outs in results.items()
        for o in outs
        if o.status == "FIXED" and (o.expect == "stop" or o.verdict != "CORRECT")
    ]


def report(results: dict[str, list[Result]]) -> list[str]:
    bad = wrongly_safe(results)
    return [
        "## Pulumi (EC2.19, S3.8, IAM.21)",
        "",
        "The same three fix types on Pulumi programs in TypeScript and Python, mapped through a "
        "`pulumi stack export`, plus the traps that must stop the run (a computed value, a "
        "component resource, a repeated name, an undeployed rule, a program that differs from "
        "the export, drift). Validation is static; `pulumi preview` is not run. PosturaNet only.",
        "",
        *summary("Contender", results),
        "",
        f"**Wrongly reported safe: {len(bad)}**" + (f" ({', '.join(bad)})" if bad else ""),
        "",
        *per_case([(c.id, c.title, c.why, c.expect) for c in CASES], results),
    ]
