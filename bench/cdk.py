"""AWS CDK benchmark: the same three fix types (open security group, public bucket, wildcard
IAM policy) when the source is a CDK app in TypeScript or Python.

Every case runs the real pipeline (`run_fix`, check mode) on a copy of
`tests/fixtures/cdk/ts-app` or `py-app` with one edit to the program or the synthesized
template, against read-only AWS doubles that return the deployed template and the live group.
Ground truth is the same as the CloudFormation family's (same evidence fixtures).

`cdk synth` is stood in for by `MiniSynth`: it copies the app's cloud assembly and rewrites
the target resource from the edited program with the bench's own regexes, not PosturaNet's
source parser, so the bench doesn't grade PosturaNet with its own code. A fix is scored on
that synthesized resource.
shortcut: MiniSynth only reads the literal shapes the fixtures use; swap in a real
`cdk synth` once aws-cdk is installed in CI.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

ROOT = Path(__file__).resolve().parent.parent

from bench.cases import END  # noqa: E402
from bench.cfn import IAM_REQUIRED, SG_HOSTILE, SG_LEGIT, _covers  # noqa: E402
from bench.common import Expect, Result, per_case, summary  # noqa: E402
from posturanet import cfn  # noqa: E402
from posturanet.aws.readonly import ReadOnlyClient  # noqa: E402
from posturanet.cfn.template import get, parse, value  # noqa: E402
from posturanet.evidence import FileSource  # noqa: E402
from posturanet.iamfix.shrink import targeted  # noqa: E402
from posturanet.models.config import load_config  # noqa: E402
from posturanet.pipeline import Context, run_fix  # noqa: E402
from posturanet.synth.sg_rules import Rule  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
Family = Literal["sg", "s3", "iam"]
Lang = Literal["ts", "py"]

# Per family: (finding, evidence, logical id).
FAMILY: dict[str, tuple[str, str, str]] = {
    "sg": ("sg_ssh_open.json", "flows/bastion_90d.json", "BastionSg1A2B3C4D"),
    "s3": ("s3_assets_public.json", "s3/public_unused.json", "Assets1C2D3E4F"),
    "iam": ("iam21_app.json", "iam/app.json", "AppPolicy5A6B7C8D"),
}
# Per language: (fixture app, program file per family, template per family).
APP: dict[str, tuple[str, dict[str, str], dict[str, str]]] = {
    "ts": ("ts-app",
           {"sg": "lib/network-stack.ts", "s3": "lib/storage-stack.ts",
            "iam": "lib/iam-stack.ts"},
           {"sg": "network.template.json", "s3": "storage.template.json",
            "iam": "iam.template.json"}),
    "py": ("py-app", dict.fromkeys(("sg", "s3", "iam"), "stacks/platform.py"),
           dict.fromkeys(("sg", "s3", "iam"), "assembly-Prod/Prodplatform1F2E3D4C.template.json")),
}  # fmt: skip

Resources = dict[str, Any]


# --- MiniSynth: the bench's own source → template rewrite ----------------------------------

_PEER = r"(?:ec2\.)?Peer\.(anyIpv4|any_ipv4|ipv4)\(\s*(?:['\"]([^'\"]+)['\"])?\s*\)"
_SG_CALL = re.compile(
    r"(?:bastionSg|bastion_sg)\s*\.\s*"
    r"(?:addIngressRule|add_ingress_rule|connections\.allowFrom|connections\.allow_from)\(\s*"
    + _PEER
    + r"\s*,\s*(?:ec2\.)?Port\.tcp\((\d+)\)"
)
_ANY_V4 = re.compile(
    r"(?:bastionSg|bastion_sg)\s*\.\s*connections\.(?:allowFromAnyIpv4|allow_from_any_ipv4)"
    r"\(\s*(?:ec2\.)?Port\.tcp\((\d+)\)"
)
_ACTIONS = re.compile(r"['\"]?(?:actions|Action)['\"]?\s*[:=]\s*\[([^\]]*)\]")
_L1_ENTRY = re.compile(r"cidrIp:\s*'([^']+)',\s*ipProtocol:\s*'tcp',\s*fromPort:\s*(\d+)")


def _rebuild(family: str, program: str, res: Resources, logical: str) -> None:
    props = res[logical]["Properties"]
    if family == "sg":
        props["SecurityGroupIngress"] = [
            {"CidrIp": "0.0.0.0/0" if kind != "ipv4" else cidr, "FromPort": int(port),
             "ToPort": int(port), "IpProtocol": "tcp"}
            for kind, cidr, port in _SG_CALL.findall(program)
        ] + [{"CidrIp": "0.0.0.0/0", "FromPort": int(p), "ToPort": int(p), "IpProtocol": "tcp"}
             for p in _ANY_V4.findall(program)] + [
            {"CidrIp": cidr, "FromPort": int(p), "ToPort": int(p), "IpProtocol": "tcp"}
            for cidr, p in _L1_ENTRY.findall(program)]  # fmt: skip
        for lid in [k for k, v in res.items() if v["Type"] == "AWS::EC2::SecurityGroupIngress"]:
            path = res[lid]["Metadata"]["aws:cdk:path"]
            l1 = path.rsplit("/", 1)[-1]
            if "CidrIp" in res[lid]["Properties"] and f"'{l1}'" not in program:
                del res[lid]  # an L1 CfnSecurityGroupIngress the edit removed
    elif family == "s3":
        if "BLOCK_ALL" in program or "restrictPublicBuckets: true" in program:
            props["PublicAccessBlockConfiguration"] = dict.fromkeys(
                ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls",
                 "RestrictPublicBuckets"), True,
            )  # fmt: skip
    else:
        found = _ACTIONS.search(program)
        if found:
            actions = re.findall(r"['\"]([^'\"]+)['\"]", found.group(1))
            props["PolicyDocument"]["Statement"][0]["Action"] = (
                actions[0] if len(actions) == 1 else actions
            )


@dataclass
class MiniSynth:
    family: str
    lang: str
    fail: str | None = None
    last: Resources = field(default_factory=dict)

    def synth(self, app: Path, out: Path) -> str | None:
        _, programs, templates = APP[self.lang]
        shutil.copytree(app / "cdk.out", out, dirs_exist_ok=True)
        path = out / templates[self.family]
        doc = json.loads(path.read_text("utf-8"))
        program = (app / programs[self.family]).read_text("utf-8")
        _rebuild(self.family, program, doc["Resources"], FAMILY[self.family][2])
        path.write_text(json.dumps(doc), "utf-8")
        self.last = doc["Resources"]
        return self.fail


# --- cases ----------------------------------------------------------------------------------

Edit = tuple[str, str]  # (old, new) in the family's program file


@dataclass
class CdkCase:
    id: str
    family: Family
    lang: Lang
    title: str
    why: str
    expect: Expect
    exit_code: int = 0  # how the run must end: 0 fixed, 3 stopped unknown, 4 validation fail
    says: str = ""  # the stop must give this reason
    edits: list[Edit] = field(default_factory=list)
    extra: dict[str, str] = field(default_factory=dict)  # more program files
    template: Callable[[Resources], None] | None = None  # change the synthesized assembly
    deployed: Callable[[Resources], None] | None = None  # the stack runs a different template
    live: list[dict[str, Any]] | None = None  # the live group's ingress, when changed by hand
    synth_fails: str | None = None


def _no_metadata(res: Resources) -> None:
    del res["BastionSg1A2B3C4D"]["Metadata"]


def _connections(res: Resources) -> None:
    res["BastionSg1A2B3C4D"]["Properties"]["SecurityGroupIngress"].append(
        {"CidrIp": "10.0.8.0/24", "FromPort": 5432, "ToPort": 5432, "IpProtocol": "tcp"}
    )


def _peer_group(res: Resources) -> None:
    res["BastionSgfromnetworkWebSgE5F6A7B8443"] = {
        "Type": "AWS::EC2::SecurityGroupIngress",
        "Properties": {
            "GroupId": {"Fn::GetAtt": ["BastionSg1A2B3C4D", "GroupId"]},
            "SourceSecurityGroupId": {"Fn::GetAtt": ["WebSgE5F6A7B8", "GroupId"]},
            "FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
        },
        "Metadata": {"aws:cdk:path": "network/BastionSg/from networkWebSgE5F6A7B8:22"},
    }  # fmt: skip


def _l1_rdp(res: Resources) -> None:
    res["BastionRdp9A8B7C6D"] = {
        "Type": "AWS::EC2::SecurityGroupIngress",
        "Properties": {
            "GroupId": {"Fn::GetAtt": ["BastionSg1A2B3C4D", "GroupId"]},
            "CidrIp": "0.0.0.0/0", "Description": "RDP from anywhere",
            "FromPort": 3389, "ToPort": 3389, "IpProtocol": "tcp",
        },
        "Metadata": {"aws:cdk:path": "network/BastionRdp"},
    }  # fmt: skip


def _l1(res: Resources) -> None:
    res["BastionSg1A2B3C4D"]["Metadata"]["aws:cdk:path"] = "network/BastionSg"


def _l1_bucket(res: Resources) -> None:
    res["Assets1C2D3E4F"]["Metadata"]["aws:cdk:path"] = "storage/Assets"


def _l1_policy(res: Resources) -> None:
    res["AppPolicy5A6B7C8D"]["Metadata"]["aws:cdk:path"] = "iam/AppPolicy"


def _extra_statement(res: Resources) -> None:
    res["AppPolicy5A6B7C8D"]["Properties"]["PolicyDocument"]["Statement"].append(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    )  # e.g. policy.addStatements(...) in another file


def _suspended(res: Resources) -> None:
    res["Assets1C2D3E4F"]["Properties"]["VersioningConfiguration"] = {"Status": "Suspended"}


def _s3_star(res: Resources) -> None:
    res["AppPolicy5A6B7C8D"]["Properties"]["PolicyDocument"]["Statement"][0]["Action"].append(
        "s3:*"
    )


DUP_TS = """import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

export function legacyBastion(scope: Construct, vpc: ec2.IVpc): ec2.SecurityGroup {
  return new ec2.SecurityGroup(scope, 'BastionSg', { vpc, description: 'legacy bastion' });
}
"""
SSH_TS = "ec2.Peer.anyIpv4(), ec2.Port.tcp(22)"
SSH_LINE = "bastionSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'SSH from anywhere');"
WEB_LINE = "webSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443));\n"
RDP_TS = (
    "    new ec2.CfnSecurityGroupIngress(this, 'BastionRdp', {\n"
    "      groupId: bastionSg.securityGroupId,\n"
    "      ipProtocol: 'tcp',\n"
    "      fromPort: 3389,\n"
    "      toPort: 3389,\n"
    "      cidrIp: '0.0.0.0/0',\n"
    "      description: 'RDP from anywhere',\n"
    "    });\n"
)
ALLOW_TO = "    webSg.connections.allowTo(bastionSg, ec2.Port.tcp(22), 'web');" + chr(10)
OPEN_LIVE = [
    {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": c}]}
    for p, c in [(22, "0.0.0.0/0"), (9100, "10.0.0.0/16"), (3389, "0.0.0.0/0")]
]
L1_TS = (
    "const bastionSg = new ec2.SecurityGroup(this, 'BastionSg', {",
    "const bastionSg = new ec2.CfnSecurityGroup(this, 'BastionSg', {",
)
L1_SG = (
    "    const bastionSg = new ec2.SecurityGroup(this, 'BastionSg', {\n"
    "      vpc,\n"
    "      description: 'bastion',\n"
    "    });\n"
    "    bastionSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'SSH from anywhere');\n"
    "    // monitoring stays as it is\n"
    "    bastionSg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(9100), "
    "'node exporter');\n",
    "    new ec2.CfnSecurityGroup(this, 'BastionSg', {\n"
    "      groupDescription: 'bastion',\n"
    "      vpcId: vpc.vpcId,\n"
    "      securityGroupIngress: [\n"
    "        { cidrIp: '0.0.0.0/0', ipProtocol: 'tcp', fromPort: 22, toPort: 22 },\n"
    "        { cidrIp: '10.0.0.0/16', ipProtocol: 'tcp', fromPort: 9100, toPort: 9100 },\n"
    "      ],\n"
    "    });\n",
)
L1_BUCKET = (
    "new s3.Bucket(this, 'Assets', {\n"
    "      bucketName: 'acme-assets',\n"
    "      versioned: true,\n"
    "      removalPolicy: cdk.RemovalPolicy.RETAIN,\n",
    "new s3.CfnBucket(this, 'Assets', {\n"
    "      bucketName: 'acme-assets',\n"
    "      versioningConfiguration: { status: 'Enabled' },\n",
)
L1_POLICY = (
    "new iam.ManagedPolicy(this, 'AppPolicy', {\n"
    "      managedPolicyName: 'app',\n"
    "      statements: [\n"
    "        new iam.PolicyStatement({\n"
    "          sid: 'App',\n"
    "          actions: [\n",
    "new iam.CfnManagedPolicy(this, 'AppPolicy', {\n"
    "      managedPolicyName: 'app',\n"
    "      policyDocument: {\n"
    "        Version: '2012-10-17',\n"
    "        Statement: [{\n"
    "          Sid: 'App',\n"
    "          Effect: 'Allow',\n"
    "          Resource: '*',\n"
    "          Action: [\n",
)
L1_POLICY_TAIL = (
    "          ],\n          resources: ['*'],\n        }),\n      ],\n",
    "          ],\n        }],\n      },\n",
)

CASES: list[CdkCase] = [
    *[
        CdkCase(f"cdk-{fam}-{lang}", fam, lang, f"{title} ({name})", why, "fix")
        for fam, title, why in [
            ("sg", "Bastion SSH open to the internet",
             "`addIngressRule` calls with literal peers and ports; the template has nothing else."),
            ("s3", "Public bucket nobody uses publicly",
             "A `Bucket` with literal props; `blockPublicAccess` is added."),
            ("iam", "ec2:* and logs:* used for a few calls",
             "One `PolicyStatement` with a literal `actions` array."),
        ]
        for lang, name in [("ts", "TypeScript"), ("py", "Python")]
    ],
    CdkCase("cdk-sg-peer-traced", "sg", "ts", "Another group is a peer, traced to its call",
            "`webSg.connections.allowTo(bastionSg, Port.tcp(22))` synthesizes a standalone "
            "ingress with a group source; it is kept as is and the open CIDR rule is fixed.",
            "fix", edits=[(WEB_LINE, WEB_LINE + ALLOW_TO)],
            template=_peer_group),
    CdkCase("cdk-sg-allow-from-any", "sg", "ts", "SSH opened with `connections.allowFromAnyIpv4`",
            "The open rule comes from `connections`, with literal ports; it is replaced by "
            "`addIngressRule` calls.", "fix",
            edits=[(SSH_LINE, "bastionSg.connections.allowFromAnyIpv4(ec2.Port.tcp(22), "
                              "'SSH from anywhere');")]),
    CdkCase("cdk-sg-l1-ingress-open", "sg", "ts",
            "RDP open through a literal `CfnSecurityGroupIngress`",
            "A separate L1 ingress on the group, every prop a literal; it is removed and the "
            "synthesized rules are written as `addIngressRule` calls.", "fix",
            edits=[(WEB_LINE, WEB_LINE + RDP_TS)], template=_l1_rdp, live=OPEN_LIVE),
    CdkCase("cdk-sg-l1-ingress-untraced", "sg", "ts",
            "Standalone ingress with no construct in the file",
            "The template has a `CfnSecurityGroupIngress` on the group that isn't in the group's "
            "file; PosturaNet can't edit what it can't see.", "stop", 3,
            "no literal ingress call or CfnSecurityGroupIngress", template=_l1_rdp, live=OPEN_LIVE),
    CdkCase("cdk-sg-computed-peer", "sg", "ts", "SSH peer is `Peer.ipv4(adminCidr)`",
            "The open rule's source is a variable; its value isn't a literal in the program.",
            "stop", 3, "not a literal",
            edits=[(SSH_TS, "ec2.Peer.ipv4(adminCidr), ec2.Port.tcp(22)")]),
    CdkCase("cdk-sg-connections", "sg", "ts", "A rule comes from `connections.allowFrom`",
            "The template has a 5432 rule no literal `addIngressRule` call explains; editing "
            "the calls alone would miss it.", "stop", 3, "ingress rule(s) in the template",
            template=_connections),
    CdkCase("cdk-sg-peer-group", "sg", "ts", "A group peer with no call in the group's file",
            "`webSg.connections.allowTo(bastionSg, …)` synthesizes an "
            "`AWS::EC2::SecurityGroupIngress` with a group source.", "stop", 3,
            "literal peer call(s)", template=_peer_group),
    CdkCase("cdk-sg-duplicate-id", "sg", "ts", "Two constructs have the id `BastionSg`",
            "A helper in another file makes a second `BastionSg`; PosturaNet won't pick one.",
            "stop", 3, "constructs", extra={"lib/legacy.ts": DUP_TS}),
    CdkCase("cdk-sg-computed-id", "sg", "ts", "The construct id is computed",
            "`new ec2.SecurityGroup(this, idFor('bastion'), …)`: no literal names the "
            "construct.", "stop", 3, "BastionSg",
            edits=[("this, 'BastionSg', {", "this, idFor('bastion'), {")]),
    CdkCase("cdk-sg-l1-fix", "sg", "ts", "L1 `CfnSecurityGroup` with literal ingress",
            "`securityGroupIngress` entries are literals that match the template; the open "
            "entry is replaced in the list.", "fix", edits=[L1_SG], template=_l1),
    CdkCase("cdk-s3-l1-fix", "s3", "ts", "L1 `CfnBucket` with no public access block",
            "A `publicAccessBlockConfiguration` with all four flags is added to the props.",
            "fix", edits=[L1_BUCKET], template=_l1_bucket),
    CdkCase("cdk-iam-l1-fix", "iam", "ts", "L1 `CfnManagedPolicy` with a literal document",
            "The `policyDocument` statement's `Action` array is shrunk in place.", "fix",
            edits=[L1_POLICY, L1_POLICY_TAIL], template=_l1_policy),
    CdkCase("cdk-sg-l1", "sg", "ts", "L1 `CfnSecurityGroup` whose props don't explain the rules",
            "The template has two ingress rules; the L1's props have no `securityGroupIngress` "
            "(the calls on it don't exist on an L1).", "stop", 3, "securityGroupIngress entr",
            edits=[L1_TS], template=_l1),
    CdkCase("cdk-sg-no-metadata", "sg", "ts", "Template has no `aws:cdk:path`",
            "Path metadata was turned off (`--path-metadata false`), so nothing ties the "
            "resource to a construct.", "stop", 3, "aws:cdk:path", template=_no_metadata),
    CdkCase("cdk-sg-live-drift", "sg", "ts", "RDP rule added to the live group by hand",
            "The app matches the stack, but someone added 3389 in the console; editing the "
            "program would hide it.", "stop", 4, "outside CloudFormation",
            live=[{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": c}]}
                  for p, c in [(22, "0.0.0.0/0"), (9100, "10.0.0.0/16"),
                               (3389, "198.51.100.0/24")]]),
    CdkCase("cdk-sg-synth-fails", "sg", "py", "`cdk synth` fails on the edited app",
            "The app doesn't synthesize after the edit; nothing was checked, so no PR.", "stop",
            4, "cdk_synth", synth_fails="ModuleNotFoundError: No module named 'aws_cdk'"),
    CdkCase("cdk-s3-public-read", "s3", "ts", "`publicReadAccess: true` in the props",
            "The program asks for a public bucket on purpose; turning that off is a person's "
            "call.", "stop", 3, "publicReadAccess",
            edits=[("versioned: true,", "versioned: true,\n      publicReadAccess: true,")]),
    CdkCase("cdk-s3-drift", "s3", "py", "Deployed stack differs from the app",
            "The stack runs versioning Suspended; the app says versioned.", "stop", 4,
            "differs from stack", deployed=_suspended),
    CdkCase("cdk-iam-add-statements", "iam", "ts", "A statement comes from `addStatements`",
            "The synthesized policy has a statement the construct's props don't; a shrink of "
            "the props alone could be wrong.", "stop", 3, "one-for-one",
            template=_extra_statement),
    CdkCase("cdk-iam-computed-action", "iam", "py", "An action is a variable",
            "`actions=[\"ec2:*\", \"logs:*\", extra_action]`: it could be anything.", "stop", 3,
            "not a literal", edits=[('"logs:*"]', '"logs:*", extra_action]')]),
    CdkCase("cdk-iam-drift", "iam", "ts", "Deployed stack differs from the app",
            "The stack also allows s3:*; the app doesn't. A fix from the app would be wrong.",
            "stop", 4, "differs from stack", deployed=_s3_star),
]  # fmt: skip


# --- run ------------------------------------------------------------------------------------


def _edit_json(path: Path, change: Callable[[Resources], None]) -> None:
    doc = json.loads(path.read_text("utf-8"))
    change(doc["Resources"])
    path.write_text(json.dumps(doc, indent=1), "utf-8")


def _repo(case: CdkCase, work: Path) -> Path:
    name, programs, templates = APP[case.lang]
    repo = work / name
    shutil.copytree(FIX / "cdk" / name, repo)
    program = repo / programs[case.family]
    text = program.read_text("utf-8")
    for old, new in case.edits:
        assert old in text, (case.id, old)
        text = text.replace(old, new, 1)
    program.write_text(text, "utf-8")
    for rel, body in case.extra.items():
        (repo / rel).write_text(body, "utf-8")
    if case.template is not None:
        _edit_json(repo / "cdk.out" / templates[case.family], case.template)
    return repo


def _aws(case: CdkCase, repo: Path) -> Any:
    """Read-only doubles: the deployed template, the stack export, the live group."""
    doc = json.loads((repo / "cdk.out" / APP[case.lang][2][case.family]).read_text("utf-8"))
    if case.deployed is not None:
        case.deployed(doc["Resources"])
    stacks = json.loads((repo / "stack-resources.json").read_text("utf-8"))
    live = case.live or [
        {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": c}]}
        for p, c in [(22, "0.0.0.0/0"), (9100, "10.0.0.0/16")]
    ]

    class Fake:
        def get_template(self, **kw: Any) -> dict[str, Any]:
            return {"TemplateBody": doc}

        def describe_stack_resources(self, **kw: Any) -> dict[str, Any]:
            data: dict[str, Any] = stacks
            return data

        def describe_security_groups(self, **kw: Any) -> dict[str, Any]:
            return {"SecurityGroups": [{"GroupId": kw["GroupIds"][0], "IpPermissions": live}]}

    return lambda service: ReadOnlyClient(Fake(), service)


def _score(case: CdkCase, synthesized: Resources | None, note: str) -> Result:
    if synthesized is None:
        return Result("PosturaNet", "STOPPED", case.expect, note=note)
    logical = FAMILY[case.family][2]
    t = parse(json.dumps({"Resources": synthesized}), Path("synth.template.json"))
    node = t.resources[logical]
    res = cfn.CfnResource("bench", logical, value(get(node, "Type")), t, node, 1)
    out = Result("PosturaNet", "FIXED", case.expect, note=note)
    if case.family == "sg":
        rules = cfn.parse_sg(res).rules()

        def admitted(ip: str, port: int) -> bool:
            return any(r.admits(Rule(f"{ip}/32", port, port, "tcp").net, port, "tcp")
                       for r in rules)  # fmt: skip

        out.allowed = [r.label() for r in rules]
        out.broken = [f"{ip}:{p}" for ip, p in SG_LEGIT if not admitted(ip, p)]
        out.exposed = [f"{ip}:{p}" for ip, p in SG_HOSTILE if admitted(ip, p)]
    elif case.family == "s3":
        flags = cfn.s3_flags(res)
        out.exposed = [k for k, v in flags.items() if v is not True]
        out.allowed = ["Block Public Access: " + ("all on" if not out.exposed else "partial")]
    else:
        actions = [a for s in cfn.parse_policy(res).statements for a in s.actions or []]
        out.allowed = actions
        out.broken = [a for a in IAM_REQUIRED if not any(_covers(p, a) for p in actions)]
        out.exposed = [a for a in actions if targeted("IAM.21", a)]
    return out


def posturanet(case: CdkCase, work: Path) -> tuple[Result, int]:
    repo = _repo(case, work)
    config, _ = load_config(repo)
    finding, evidence, _ = FAMILY[case.family]
    runner = MiniSynth(case.family, case.lang, case.synth_fails)
    ctx = Context(
        mode="check",
        evidence=FileSource(FIX / evidence),
        aws=_aws(case, repo),
        cdk=runner,
        clock=lambda: END,
    )
    record = run_fix(str(FIX / "findings" / finding), repo, config, ctx)
    if record.result != "VALIDATED" or record.diff is None:
        stops = [s for s in record.stages if s.status.value in ("fail", "unknown")]
        why = "; ".join(f"{s.name} {s.status.value}: {s.summary}" for s in stops)
        if record.validation is not None:
            why += "; " + "; ".join(
                f"{c.id} {c.result.value}: {c.detail}"
                for c in record.validation.checks
                if c.result.value in ("fail", "error")
            )
        return _score(case, None, why or record.result), record.exit_code
    return _score(case, runner.last, record.result_detail or ""), record.exit_code


def run() -> dict[str, list[Result]]:
    return {c.id: [run_case(c)[0]] for c in CASES}


def run_case(case: CdkCase) -> tuple[Result, int]:
    with tempfile.TemporaryDirectory() as tmp:
        return posturanet(case, Path(tmp))


def wrongly_safe(results: dict[str, list[Result]]) -> list[str]:
    """Cases where PosturaNet validated a fix that is unsafe, or where no safe fix exists."""
    return [
        cid
        for cid, outs in results.items()
        for o in outs
        if o.status == "FIXED" and (o.expect == "stop" or o.verdict != "CORRECT")
    ]


def report(results: dict[str, list[Result]]) -> list[str]:
    bad = wrongly_safe(results)
    return [
        "## AWS CDK (EC2.19, S3.8, IAM.21)",
        "",
        "The same three fix types on CDK apps in TypeScript and Python, plus the traps that "
        "must stop the run (a computed peer, id or action, rules or statements the construct's "
        "literals don't explain, a duplicate id, an L1 whose props don't match, no path "
        "metadata, a failed synth, a stack that differs from the app). `cdk synth` is a bench "
        "stand-in that rewrites the target from the edited program with its own regexes. "
        "PosturaNet only.",
        "",
        *summary("Contender", results),
        "",
        f"**Wrongly reported safe: {len(bad)}**" + (f" ({', '.join(bad)})" if bad else ""),
        "",
        *per_case([(c.id, c.title, c.why, c.expect) for c in CASES], results),
    ]


__all__ = ["CASES", "report", "run", "run_case", "wrongly_safe"]
