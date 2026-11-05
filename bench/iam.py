"""IAM least-privilege benchmark (IAM.1 / IAM.21 on one customer-managed policy): does replacing
a wildcard with "the actions in use" take away anything the workload really calls?

Ground truth per case is `required`: every action the workload calls, including ones IAM's
last-accessed data can't show (S3 object reads, `iam:PassRole`, a yearly job last run before
the tracking period). The evidence each tool sees is what IAM would report, nothing more.
"""

from __future__ import annotations

import fnmatch
import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from bench.cases import END  # noqa: E402
from bench.common import Expect, Result, per_case, summary  # noqa: E402
from fakes import IamTerraform  # noqa: E402
from posturanet.evidence import FileSource  # noqa: E402
from posturanet.iamfix import contract as iamcontract  # noqa: E402
from posturanet.iamfix.shrink import targeted  # noqa: E402
from posturanet.models.config import load_config  # noqa: E402
from posturanet.models.iam import IamAllowed  # noqa: E402
from posturanet.pipeline import Context, run_fix  # noqa: E402

REPO = ROOT / "tests" / "fixtures" / "tf" / "iam"
FINDING = ROOT / "tests" / "fixtures" / "findings" / "iam21_app.json"
ARN = "arn:aws:iam::123456789012:policy/app"
TODAY = END.date()


@dataclass(frozen=True)
class Svc:
    """What IAM last-accessed reports for one service."""

    namespace: str
    used: dict[str, int] = field(default_factory=dict)  # action -> days since last use
    unused: tuple[str, ...] = ()  # tracked actions with no use in the tracking period
    action_level: bool = True
    accessed: bool = True


@dataclass
class IamCase:
    id: str
    title: str
    why: str
    expect: Expect
    actions: list[str]  # the policy's one Allow statement
    required: list[str]  # ground truth: what the workload calls
    services: list[Svc]
    control: str = "IAM.21"
    age_days: int = 500
    reviewed: list[str] = field(default_factory=list)  # approved contract: reviewed_services
    human: list[str] = field(default_factory=list)  # approved contract: must_allow by hand


def _covers(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def evidence(case: IamCase) -> dict[str, object]:
    def day(back: int | None) -> str | None:
        return None if back is None else (TODAY - timedelta(days=back)).isoformat()

    services = []
    for s in case.services:
        last = min(s.used.values()) if s.used else None
        services.append(
            {
                "namespace": s.namespace,
                "last_accessed": day(last) if s.accessed else None,
                "action_level": s.action_level,
                "actions": [
                    *(
                        {"name": a.split(":", 1)[1], "last_accessed": day(b)}
                        for a, b in s.used.items()
                    ),
                    *({"name": a.split(":", 1)[1], "last_accessed": None} for a in s.unused),
                ]
                if s.action_level
                else [],
            }
        )
    return {
        "policy_arn": ARN,
        "created": (TODAY - timedelta(days=case.age_days)).isoformat(),
        "principals": ["role/app"],
        "services": services,
    }


def _hcl(actions: list[str]) -> str:
    listed = ", ".join(json.dumps(a) for a in actions)
    return (
        'resource "aws_iam_policy" "app" {\n'
        '  name = "app"\n'
        "  policy = jsonencode({\n"
        '    Version = "2012-10-17"\n'
        "    Statement = [\n"
        "      {\n"
        '        Effect   = "Allow"\n'
        f"        Action   = [{listed}]\n"
        '        Resource = "*"\n'
        "      },\n"
        "    ]\n"
        "  })\n"
        "}\n"
    )


def _repo(case: IamCase, work: Path) -> tuple[Path, Path, Path]:
    repo = work / "repo"
    shutil.copytree(REPO, repo)
    (repo / "main.tf").write_text(_hcl(case.actions), encoding="utf-8")
    state = json.loads((REPO / "state.fixture.json").read_text(encoding="utf-8"))
    app = next(r for r in state["resources"] if r["name"] == "app")
    app["instances"][0]["attributes"]["policy"] = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": case.actions, "Resource": "*"}],
        }
    )
    state["resources"] = [app]
    (repo / "state.fixture.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    finding = work / "finding.json"
    finding.write_text(
        FINDING.read_text(encoding="utf-8").replace("IAM.21", case.control), encoding="utf-8"
    )
    ev = work / "iam.json"
    ev.write_text(json.dumps(evidence(case), indent=1), encoding="utf-8")
    return repo, finding, ev


def _score(case: IamCase, tool: str, allowed: list[str] | None, note: str = "") -> Result:
    if allowed is None:
        return Result(tool, "STOPPED", case.expect, note=note)
    out = Result(tool, "FIXED", case.expect, allowed=allowed)
    out.broken = [a for a in case.required if not any(_covers(p, a) for p in allowed)]
    out.exposed = [a for a in allowed if targeted(case.control, a)]
    return out


def posturanet(case: IamCase, work: Path) -> Result:
    repo, finding, ev = _repo(case, work)
    config, _ = load_config(repo)
    if case.reviewed or case.human:
        _approve(case, repo, config.contracts.dir, finding, ev)
    ctx = Context(
        mode="check", evidence=FileSource(ev), terraform=IamTerraform("app"), clock=lambda: END
    )
    record = run_fix(str(finding), repo, config, ctx)
    if record.result != "VALIDATED" or record.diff is None:
        stop = next((s for s in record.stages if s.status.value in ("fail", "unknown")), None)
        why = stop.summary if stop else record.result
        if stop and stop.details:
            why += ": " + stop.details[0]
        return _score(case, "PosturaNet", None, why)
    return _score(case, "PosturaNet", list(record.diff.rules_after))


def _approve(case: IamCase, repo: Path, contracts_dir: str, finding: Path, ev: Path) -> None:
    """Let PosturaNet write its draft, then approve it the way a reviewer would."""
    config, _ = load_config(repo)
    run_fix(
        str(finding),
        repo,
        config,
        Context(mode="check", evidence=FileSource(ev), clock=lambda: END),
    )
    path = repo / contracts_dir / "aws_iam_policy.app.yaml"
    draft = iamcontract.load(path)
    assert draft is not None, "PosturaNet writes a draft contract"
    iamcontract.write(
        path,
        draft.model_copy(
            update={
                "status": "approved",
                "reviewed_services": case.reviewed,
                "must_allow": [
                    *draft.must_allow,
                    *(IamAllowed(action=a, source="human", owner="@platform") for a in case.human),
                ],
                "needs_review": [],
            }
        ),
    )


def used_only(case: IamCase, work: Path) -> Result:
    """Swap each wildcard for the tracked actions last-accessed shows as used, with no gates
    (the shape of a policy generated straight from activity data)."""
    used = {a for s in case.services if s.action_level for a in s.used}
    kept = [a for a in case.actions if not targeted(case.control, a)]
    added = {
        a
        for p in case.actions
        if targeted(case.control, p)
        for a in used
        if _covers(p, a) and not any(_covers(k, a) for k in kept)
    }
    return _score(case, "Used actions only", sorted({*kept, *added}, key=str.lower))


def remove_wildcard(case: IamCase, work: Path) -> Result:
    """Delete the wildcard and keep the rest (a common manual fix)."""
    return _score(
        case, "Remove wildcard", [a for a in case.actions if not targeted(case.control, a)]
    )


CONTENDERS: list[Callable[[IamCase, Path], Result]] = [posturanet, used_only, remove_wildcard]

_EC2 = Svc("ec2", {"ec2:DescribeInstances": 1, "ec2:DescribeVolumes": 3}, ("ec2:RunInstances",))

CASES = [
    IamCase(
        "iam-ec2-describe",
        "ec2:* used only for Describe calls",
        "A monitoring role with a service wildcard; every call it makes is tracked.",
        "fix",
        ["ec2:*"],
        ["ec2:DescribeInstances", "ec2:DescribeVolumes"],
        [_EC2],
    ),
    IamCase(
        "iam-unused-service",
        "Wildcard on a service never used",
        "rds:* sits next to an explicit EC2 action and was never used.",
        "fix",
        ["rds:*", "ec2:DescribeInstances"],
        ["ec2:DescribeInstances"],
        [Svc("rds", accessed=False), _EC2],
    ),
    IamCase(
        "iam-rare-job-in-window",
        "Snapshot job that ran 200 days ago",
        "A twice-yearly job; IAM still tracks its last use.",
        "fix",
        ["rds:*"],
        ["rds:DescribeDBInstances", "rds:CreateDBSnapshot"],
        [Svc("rds", {"rds:DescribeDBInstances": 1, "rds:CreateDBSnapshot": 200})],
    ),
    IamCase(
        "iam-rare-job-outside-tracking",
        "Yearly job last run before the tracking period",
        "A yearly audit export last ran 430 days ago, past IAM's ~400-day tracking period.",
        "stop",
        ["rds:*"],
        ["rds:DescribeDBInstances", "rds:StartExportTask"],
        [Svc("rds", {"rds:DescribeDBInstances": 1}, ("rds:StartExportTask",))],
    ),
    IamCase(
        "iam-s3-data-plane",
        "s3:* for an app that reads and writes objects",
        "Object reads and writes aren't in last-accessed data; only ListAllMyBuckets shows.",
        "stop",
        ["s3:*"],
        ["s3:ListAllMyBuckets", "s3:GetObject", "s3:PutObject"],
        [Svc("s3", {"s3:ListAllMyBuckets": 2})],
    ),
    IamCase(
        "iam-s3-reviewed",
        "Same app, object actions confirmed by the team",
        "The owners list GetObject and PutObject in the contract and review s3.",
        "fix",
        ["s3:*"],
        ["s3:ListAllMyBuckets", "s3:GetObject", "s3:PutObject"],
        [Svc("s3", {"s3:ListAllMyBuckets": 2})],
        reviewed=["s3"],
        human=["s3:GetObject", "s3:PutObject"],
    ),
    IamCase(
        "iam-passrole",
        "iam:* for a deployer that passes a role",
        "The deployer passes a role to ECS; IAM never tracks iam:PassRole.",
        "stop",
        ["iam:*"],
        ["iam:GetRole", "iam:PassRole"],
        [Svc("iam", {"iam:GetRole": 1}, ("iam:CreateRole",))],
    ),
    IamCase(
        "iam-passrole-kept",
        "Same deployer, PassRole kept by the team",
        "The owners add iam:PassRole to must_allow.",
        "fix",
        ["iam:*"],
        ["iam:GetRole", "iam:PassRole"],
        [Svc("iam", {"iam:GetRole": 1}, ("iam:CreateRole",))],
        human=["iam:PassRole"],
    ),
    IamCase(
        "iam-no-action-data",
        "Service used without action-level data",
        "ssm was used, but IAM reports it only at service level.",
        "stop",
        ["ssm:*"],
        ["ssm:GetParameter"],
        [Svc("ssm", {"ssm:GetParameter": 1}, action_level=False)],
    ),
    IamCase(
        "iam-admin-star",
        "Admin policy (*) used for EC2 reads and logs",
        "The workload never passes a role, but nothing in the data can show that.",
        "fix",
        ["*"],
        ["ec2:DescribeInstances", "logs:PutLogEvents"],
        [_EC2, Svc("logs", {"logs:PutLogEvents": 1})],
        control="IAM.1",
    ),
    IamCase(
        "iam-admin-star-reviewed",
        "Same admin policy, IAM reviewed by the team",
        "The owners confirm the role passes no roles and review iam.",
        "fix",
        ["*"],
        ["ec2:DescribeInstances", "logs:PutLogEvents"],
        [_EC2, Svc("logs", {"logs:PutLogEvents": 1})],
        control="IAM.1",
        reviewed=["iam"],
    ),
    IamCase(
        "iam-young-policy",
        "Policy created 10 days ago, weekly job not yet seen",
        "A weekly snapshot job hasn't run since the policy was created.",
        "stop",
        ["ec2:*"],
        ["ec2:DescribeInstances", "ec2:CreateSnapshot"],
        [Svc("ec2", {"ec2:DescribeInstances": 1}, ("ec2:CreateSnapshot",))],
        age_days=10,
    ),
]


def run() -> dict[str, list[Result]]:
    results: dict[str, list[Result]] = {}
    for case in CASES:
        results[case.id] = []
        for contender in CONTENDERS:
            with tempfile.TemporaryDirectory() as tmp:
                results[case.id].append(contender(case, Path(tmp)))
    return results


def report(results: dict[str, list[Result]]) -> list[str]:
    return [
        "## IAM least privilege (IAM.1, IAM.21)",
        "",
        *summary("Contender", results),
        "",
        *per_case([(c.id, c.title, c.why, c.expect) for c in CASES], results),
    ]


__all__ = ["CASES", "report", "run"]
