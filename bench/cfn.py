"""CloudFormation and SAM benchmark: the same three fix types (open security group, public
bucket, wildcard IAM policy) when the source is a template instead of Terraform.

Every case runs the real pipeline (`run_fix`, check mode) on a copy of
`tests/fixtures/cfn/basic` with one template swapped in, against read-only AWS doubles that
return the deployed template and the live group. Ground truth is fixed per family by the
evidence fixture each case reads; what changes is the template's shape (YAML, JSON, short-form
intrinsics) and the traps that must stop the run: a rule field PosturaNet can't read, a
resource the SAM transform generates, two templates that define the same resource, and a
deployed stack that differs from the repo. A fix is scored on the edited template itself.
"""

from __future__ import annotations

import fnmatch
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

ROOT = Path(__file__).resolve().parent.parent

from bench.cases import END, PROBE  # noqa: E402
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
BASIC = FIX / "cfn" / "basic"
Family = Literal["sg", "s3", "iam"]

# Per family: (finding, evidence, stack, logical id, physical id, template file in BASIC).
FAMILY: dict[str, tuple[str, str, str, str, str, str]] = {
    "sg": ("sg_ssh_open.json", "flows/bastion_90d.json", "network", "BastionSG",
           "sg-0a91f3c2", "templates/network.yaml"),
    "s3": ("s3_assets_public.json", "s3/public_unused.json", "storage", "AssetsBucket",
           "acme-assets", "templates/storage.yaml"),
    "iam": ("iam21_app.json", "iam/app.json", "iam", "AppPolicy",
            "arn:aws:iam::123456789012:policy/app", "templates/iam.json"),
}  # fmt: skip

# Ground truth, read off the evidence fixtures above.
SG_LEGIT = [("10.0.4.12", 22), ("10.0.4.37", 22), ("10.0.5.9", 22), ("10.0.0.5", 9100)]
SG_HOSTILE = [(PROBE, 22), ("198.51.100.23", 22)]  # fresh internet address, one-off scanner
IAM_REQUIRED = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "logs:CreateLogStream"]


def _fixture(family: str) -> str:
    return (BASIC / FAMILY[family][5]).read_text(encoding="utf-8")


# --- templates ------------------------------------------------------------------------------

SG_RULES = [
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0",
     "Description": "SSH from anywhere"},
    {"IpProtocol": "tcp", "FromPort": 9100, "ToPort": 9100, "CidrIp": "10.0.0.0/16",
     "Description": "node exporter"},
]  # fmt: skip
SG_JSON = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"VpcId": {"Type": "AWS::EC2::VPC::Id"}},
        "Resources": {
            "BastionSG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "bastion",
                    "VpcId": {"Ref": "VpcId"},
                    "SecurityGroupIngress": SG_RULES,
                },
            }
        },
    },
    indent=2,
)
SG_YAML = """AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
Resources:
  BastionSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: bastion
      VpcId:
        Ref: VpcId
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
          Description: SSH from anywhere
        - IpProtocol: tcp
          FromPort: 9100
          ToPort: 9100
          CidrIp: 10.0.0.0/16
          Description: node exporter
"""
SG_SHORT = _fixture("sg")  # !Sub, !Ref, !GetAtt, flow-style rules on a second group
SG_INTRINSIC = SG_SHORT.replace(
    "Parameters:\n", "Parameters:\n  AdminCidr:\n    Type: String\n"
).replace(
    "CidrIp: 0.0.0.0/0\n          Description: SSH",
    "CidrIp: !Ref AdminCidr\n" + " " * 10 + "Description: SSH",
)

S3_YAML = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  AssetsBucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Properties:
      BucketName: acme-assets
      VersioningConfiguration:
        Status: Enabled
"""
S3_JSON = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AssetsBucket": {
                "Type": "AWS::S3::Bucket",
                "DeletionPolicy": "Retain",
                "Properties": {
                    "BucketName": "acme-assets",
                    "VersioningConfiguration": {"Status": "Enabled"},
                },
            }
        },
    },
    indent=2,
)
S3_SHORT = S3_YAML + (
    "      Tags:\n"
    "        - Key: stack\n"
    "          Value: !Ref AWS::StackName\n"
    "        - Key: logs\n"
    '          Value: !Sub "${AWS::StackName}-logs"\n'
)
S3_INTRINSIC = (
    S3_YAML.replace("Resources:\n", "Parameters:\n  Block:\n    Type: String\nResources:\n")
    + "      PublicAccessBlockConfiguration:\n"
    "        BlockPublicAcls: !Ref Block\n"
    "        IgnorePublicAcls: true\n"
)

IAM_JSON = _fixture("iam")
IAM_YAML = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  AppPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: app
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: App
            Effect: Allow
            Action:
              - ec2:*
              - logs:*
            Resource: "*"
"""
IAM_SHORT = IAM_YAML.replace(
    "Resources:\n", "Parameters:\n  AppRoleName:\n    Type: String\nResources:\n"
).replace(
    "      ManagedPolicyName: app\n",
    '      ManagedPolicyName: !Sub "${AWS::StackName}-app"\n'
    "      Roles:\n        - !Ref AppRoleName\n",
)
IAM_INTRINSIC = IAM_YAML.replace(
    "Resources:\n", "Parameters:\n  ExtraAction:\n    Type: String\nResources:\n"
).replace("              - logs:*\n", "              - logs:*\n              - !Ref ExtraAction\n")


# --- cases ----------------------------------------------------------------------------------


@dataclass
class CfnCase:
    id: str
    family: Family
    title: str
    why: str
    expect: Expect
    template: str
    file: str = ""  # repo path for `template`; defaults to the family's fixture file
    exit_code: int = 0  # how the run must end: 0 fixed, 3 stopped unknown, 4 validation fail
    says: str = ""  # the stop must give this reason
    extra: dict[str, str] = field(default_factory=dict)  # more templates in the repo
    sam_logical: str = ""  # the stack export maps the resource to this SAM-generated id
    deployed: str | None = None  # the template the stack runs, when it differs from the repo
    live: list[dict[str, Any]] | None = None  # BastionSG's live ingress, when changed by hand


def _shapes(family: Family, name: str, yaml_: str, json_: str, short: str) -> list[CfnCase]:
    base = FAMILY[family][5].rsplit(".", 1)[0]
    return [
        CfnCase(f"cfn-{family}-yaml", family, f"{name}, YAML template",
                "Long-form YAML, nothing PosturaNet can't read.", "fix", yaml_, f"{base}.yaml"),
        CfnCase(f"cfn-{family}-json", family, f"{name}, JSON template",
                "The same resource as a JSON template; the edit keeps JSON layout.", "fix",
                json_, f"{base}.json"),
        CfnCase(f"cfn-{family}-short-form", family, f"{name}, short-form intrinsics",
                "`!Ref` / `!Sub` / `!GetAtt` elsewhere in the template; the rule fields are "
                "literal, so a fix is still safe.", "fix", short, f"{base}.yaml"),
    ]  # fmt: skip


SAM = (
    "The stack export maps the finding's resource to a logical id the SAM transform generates; "
    "no template line defines it."
)
AMBIGUOUS = "Two templates in the repo define the same logical id; PosturaNet won't pick one."

CASES: list[CfnCase] = [
    *_shapes("sg", "Bastion SSH open to the internet", SG_YAML, SG_JSON, SG_SHORT),
    CfnCase("cfn-sg-intrinsic-cidr", "sg", "SSH rule's CidrIp is `!Ref AdminCidr`",
            "The open rule's source is a parameter (deployed as 0.0.0.0/0); changing it means "
            "changing the stack's parameters, not the template.", "stop",
            SG_INTRINSIC, exit_code=3, says="never rewrites a parameterised value"),
    CfnCase("cfn-sg-sam-generated", "sg", "Group generated by the SAM transform", SAM, "stop",
            SG_SHORT, exit_code=3, says="SAM transform", sam_logical="ThumbnailFunctionSG"),
    CfnCase("cfn-sg-ambiguous", "sg", "BastionSG in two templates", AMBIGUOUS, "stop", SG_SHORT,
            exit_code=3, says="defined in 2 templates",
            extra={"templates/network-dev.yaml": SG_SHORT}),
    CfnCase("cfn-sg-live-drift", "sg", "RDP rule added to the live group by hand",
            "The template matches the stack, but someone added 3389 from 198.51.100.0/24 in "
            "the console; editing the template would hide it.", "stop", SG_SHORT, exit_code=4,
            says="outside CloudFormation",
            live=[{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": c}]}
                  for p, c in [(22, "0.0.0.0/0"), (9100, "10.0.0.0/16"),
                               (3389, "198.51.100.0/24")]]),
    *_shapes("s3", "Public bucket nobody uses publicly", S3_YAML, S3_JSON, S3_SHORT),
    CfnCase("cfn-s3-intrinsic-flag", "s3", "BlockPublicAcls is `!Ref Block`",
            "One Block Public Access flag is a parameter, deployed as false; turning it on "
            "means changing the stack's parameters, not the template.",
            "stop", S3_INTRINSIC, "templates/storage.yaml", exit_code=3,
            says="never rewrites a parameterised value"),
    CfnCase("cfn-s3-sam-generated", "s3", "Bucket generated by the SAM transform", SAM, "stop",
            _fixture("s3"), exit_code=3, says="SAM transform",
            sam_logical="ThumbnailFunctionBucket"),
    CfnCase("cfn-s3-ambiguous", "s3", "AssetsBucket in two templates", AMBIGUOUS, "stop",
            _fixture("s3"), exit_code=3, says="defined in 2 templates",
            extra={"templates/storage-dev.yaml": S3_YAML}),
    CfnCase("cfn-s3-drift", "s3", "Deployed stack differs from the repo",
            "The stack runs versioning Suspended; the repo says Enabled.", "stop",
            _fixture("s3"), exit_code=4, says="differs from stack storage",
            deployed=_fixture("s3").replace("Status: Enabled", "Status: Suspended")),
    *_shapes("iam", "ec2:* and logs:* used for a few calls", IAM_YAML, IAM_JSON, IAM_SHORT),
    CfnCase("cfn-iam-intrinsic-action", "iam", "An Action entry is `!Ref ExtraAction`",
            "One action is a parameter; it could be anything, so no shrink is safe.", "stop",
            IAM_INTRINSIC, "templates/iam.yaml", exit_code=3, says="has no known value"),
    CfnCase("cfn-iam-sam-generated", "iam", "Policy generated by the SAM transform", SAM,
            "stop", IAM_JSON, exit_code=3, says="SAM transform",
            sam_logical="ThumbnailFunctionPolicy"),
    CfnCase("cfn-iam-ambiguous", "iam", "AppPolicy in two templates", AMBIGUOUS, "stop",
            IAM_JSON, exit_code=3, says="defined in 2 templates",
            extra={"templates/iam-dev.yaml": IAM_YAML}),
    CfnCase("cfn-iam-drift", "iam", "Deployed stack differs from the repo",
            "The stack also allows s3:*; the repo doesn't. A fix from the repo would be wrong.",
            "stop", IAM_JSON, exit_code=4, says="differs from stack iam",
            deployed=IAM_JSON.replace('"logs:*"', '"logs:*",\n                "s3:*"')),
]  # fmt: skip


# --- run ------------------------------------------------------------------------------------


def _repo(case: CfnCase, work: Path) -> Path:
    repo = work / "repo"
    shutil.copytree(BASIC, repo)
    _, _, stack, logical, physical, fixture = FAMILY[case.family]
    (repo / fixture).unlink()
    for rel, text in {case.file or fixture: case.template, **case.extra}.items():
        (repo / rel).write_text(text, encoding="utf-8")
    if case.sam_logical:
        export = repo / "stack-resources.json"
        data = json.loads(export.read_text(encoding="utf-8"))
        for row in data["StackResources"]:
            if row["PhysicalResourceId"] == physical:
                row.update(StackName="storage", LogicalResourceId=case.sam_logical)
        export.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return repo


def _aws(case: CfnCase) -> Any:
    """Read-only doubles: the deployed template, the stack export, the live group."""
    body = case.deployed or case.template
    live = case.live or [
        {"IpProtocol": "tcp", "FromPort": r["FromPort"], "ToPort": r["ToPort"],
         "IpRanges": [{"CidrIp": r["CidrIp"]}]}
        for r in SG_RULES
    ]  # fmt: skip

    class Fake:
        def get_template(self, **kw: Any) -> dict[str, Any]:
            return {"TemplateBody": body}

        def describe_stacks(self, **kw: Any) -> dict[str, Any]:
            deployed = {"AdminCidr": "0.0.0.0/0", "Block": "false", "VpcId": "vpc-0example"}
            params = [{"ParameterKey": k, "ParameterValue": v} for k, v in deployed.items()]
            return {"Stacks": [{"StackName": kw["StackName"], "Parameters": params}]}

        def describe_stack_resources(self, **kw: Any) -> dict[str, Any]:
            data: dict[str, Any] = json.loads((BASIC / "stack-resources.json").read_text("utf-8"))
            return data

        def describe_security_groups(self, **kw: Any) -> dict[str, Any]:
            return {"SecurityGroups": [{"GroupId": kw["GroupIds"][0], "IpPermissions": live}]}

        # The live bucket and policy match the deployed template.
        def get_public_access_block(self, **kw: Any) -> dict[str, Any]:
            props = _deployed(body, "AWS::S3::Bucket")
            if "PublicAccessBlockConfiguration" not in props:
                raise _NoPab
            return {"PublicAccessBlockConfiguration": props["PublicAccessBlockConfiguration"]}

        def get_policy(self, **kw: Any) -> dict[str, Any]:
            return {"Policy": {"DefaultVersionId": "v1"}}

        def get_policy_version(self, **kw: Any) -> dict[str, Any]:
            doc = _deployed(body, "AWS::IAM::ManagedPolicy")["PolicyDocument"]
            return {"PolicyVersion": {"Document": doc}}

    return lambda service: ReadOnlyClient(Fake(), service)


class _NoPab(Exception):
    response = {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}  # noqa: RUF012


def _deployed(body: str, rtype: str) -> dict[str, Any]:
    resources = value(get(parse(body, Path("deployed.yaml")).root, "Resources"))
    props: dict[str, Any] = next(
        r.get("Properties", {}) for r in resources.values() if r["Type"] == rtype
    )
    return props


def _score(case: CfnCase, new: str | None, file: str, note: str) -> Result:
    if new is None:
        return Result("PosturaNet", "STOPPED", case.expect, note=note)
    _, _, stack, logical, _, _ = FAMILY[case.family]
    t = parse(new, Path(file))
    node = t.resources[logical]
    res = cfn.CfnResource(stack, logical, value(get(node, "Type")), t, node, 1)
    return score(case.family, case.expect, res, note)


def score(family: Family, expect: Expect, res: cfn.CfnResource, note: str) -> Result:
    """A validated fix, scored on the edited resource against the family's ground truth."""
    out = Result("PosturaNet", "FIXED", expect, note=note)
    if family == "sg":
        rules = cfn.parse_sg(res).rules()

        def admitted(ip: str, port: int) -> bool:
            return any(r.admits(Rule(f"{ip}/32", port, port, "tcp").net, port, "tcp")
                       for r in rules)  # fmt: skip

        out.allowed = [r.label() for r in rules]
        out.broken = [f"{ip}:{p}" for ip, p in SG_LEGIT if not admitted(ip, p)]
        out.exposed = [f"{ip}:{p}" for ip, p in SG_HOSTILE if admitted(ip, p)]
    elif family == "s3":
        flags = cfn.s3_flags(res)
        out.exposed = [k for k, v in flags.items() if v is not True]
        out.allowed = ["Block Public Access: " + ("all on" if not out.exposed else "partial")]
    else:
        actions = [a for s in cfn.parse_policy(res).statements for a in s.actions or []]
        out.allowed = actions
        out.broken = [a for a in IAM_REQUIRED if not any(_covers(p, a) for p in actions)]
        out.exposed = [a for a in actions if targeted("IAM.21", a)]
    return out


def _covers(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def posturanet(case: CfnCase, work: Path) -> tuple[Result, int]:
    repo = _repo(case, work)
    config, _ = load_config(repo)
    finding, evidence, *_ = FAMILY[case.family]
    ctx = Context(
        mode="check", evidence=FileSource(FIX / evidence), aws=_aws(case), clock=lambda: END
    )
    record = run_fix(str(FIX / "findings" / finding), repo, config, ctx)
    if record.result != "VALIDATED" or record.diff is None:
        stop = next((s for s in record.stages if s.status.value in ("fail", "unknown")), None)
        why = f"{stop.name} {stop.status.value}: {stop.summary}" if stop else record.result
        return _score(case, None, "", why), record.exit_code
    f = record.diff.files[0]
    return _score(case, f.new_content, f.path, record.result_detail or ""), record.exit_code


def run() -> dict[str, list[Result]]:
    return {c.id: [run_case(c)[0]] for c in CASES}


def run_case(case: CfnCase) -> tuple[Result, int]:
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
        "## CloudFormation and SAM (EC2.19, S3.8, IAM.21)",
        "",
        "The same three fix types on templates: YAML, JSON and short-form intrinsics, plus the "
        "traps that must stop the run (a rule field that is an intrinsic, a SAM-generated "
        "resource, a resource defined in two templates, a stack that differs from the repo). "
        "PosturaNet only; the baselines don't depend on the IaC format.",
        "",
        *summary("Contender", results),
        "",
        f"**Wrongly reported safe: {len(bad)}**" + (f" ({', '.join(bad)})" if bad else ""),
        "",
        *per_case([(c.id, c.title, c.why, c.expect) for c in CASES], results),
    ]


__all__ = ["CASES", "report", "run", "run_case", "wrongly_safe"]
