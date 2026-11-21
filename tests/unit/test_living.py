"""Living contracts (R11): refresh (FR-52), live drift (FR-53), scheduled delivery (FR-54)."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from ruamel.yaml import YAML
from typer.testing import CliRunner

from fakes import FakeGitHub, FakeTerraform
from posturanet.cli.app import app
from posturanet.contracts import load_contract, write_contract
from posturanet.deliver.github import GitHub
from posturanet.evidence import FileSource
from posturanet.gate import _load
from posturanet.iamfix import contract as iamcontract
from posturanet.living import check_live, deliver_drift, deliver_refresh, drift_marker, refresh
from posturanet.models import Confidence
from posturanet.models.config import load_config
from posturanet.models.contract import ObservedMeta, ObservedWindow
from posturanet.models.iam import IamAllowed, IamContract
from posturanet.models.s3 import Exposure, S3Contract, S3Use
from posturanet.output.console import render_gate, render_refresh
from posturanet.pipeline import Context, run_fix
from posturanet.s3fix import contract as s3contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
NOW = datetime(2026, 10, 29, tzinfo=UTC)
ADDRESS = "module.bastion.aws_security_group.this"
SG_ID = "sg-0a91f3c2"
REL = "posturanet/contracts/module.bastion.aws_security_group.this.yaml"


# --- helpers


def _approved_sg(repo: Path, flows: Path, finding: Path) -> Path:
    """Build the bastion contract from the fixture flows, then approve it as a person would."""
    config, _ = load_config(repo)
    run_fix(str(finding), repo, config, Context(mode="check", evidence=FileSource(flows), terraform=FakeTerraform()))  # fmt: skip
    path = repo / REL
    c = load_contract(path)
    assert c is not None
    write_contract(path, c.model_copy(update={"status": "approved", "approved_by": "@pat"}))
    return path


def _flows(src: Path, dest: Path, *, drop: str | None = None, add: str | None = None) -> Path:
    data = json.loads(src.read_text(encoding="utf-8"))
    recs = data["records"]
    if drop:
        recs = [r for r in recs if r["srcAddr"] != drop]
    if add:
        recs += [{**r, "srcAddr": add} for r in data["records"] if r["srcAddr"] == "10.0.4.12"]
    data["records"] = recs
    dest.write_text(json.dumps(data), encoding="utf-8")
    return dest


class _Client:
    def __init__(self, **methods: Any) -> None:
        for name, fn in methods.items():
            setattr(self, name, fn)


def _aws(clients: dict[str, _Client], account: str = "123456789012") -> Any:
    sts = _Client(get_caller_identity=lambda: {"Account": account})
    return lambda service: {"sts": sts, **clients}[service]


class _ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def _sg_groups(*perms: dict[str, Any]) -> _Client:
    def describe(GroupIds: list[str]) -> dict[str, Any]:  # noqa: N803 (boto3 casing)
        assert GroupIds == [SG_ID]
        return {"SecurityGroups": [{"GroupId": SG_ID, "IpPermissions": list(perms)}]}

    return _Client(describe_security_groups=describe)


def _ssh(*cidrs: str) -> dict[str, Any]:
    return {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": c} for c in cidrs],
    }


KEPT = ["10.0.4.12/32", "10.0.4.37/32", "10.0.5.9/32", "203.0.113.7/32"]


# --- refresh: security groups


def test_refresh_unchanged_contract_passes_and_writes_nothing(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    path = _approved_sg(tmp_repo, flows_path, sg_finding_path)
    before = path.read_text(encoding="utf-8")
    config, _ = load_config(tmp_repo)
    [r] = refresh(tmp_repo, config, target=ADDRESS, aws=None, evidence_file=flows_path, now=NOW)
    assert r.status == "PASS", r
    assert r.proposed is None and not r.additions and not r.removals
    assert path.read_text(encoding="utf-8") == before


def test_refresh_proposes_new_user_and_flags_unseen_one(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path, tmp_path: Path
) -> None:
    path = _approved_sg(tmp_repo, flows_path, sg_finding_path)
    before = path.read_text(encoding="utf-8")
    changed = _flows(flows_path, tmp_path / "f.json", drop="10.0.5.9", add="10.0.6.20")
    config, _ = load_config(tmp_repo)
    [r] = refresh(tmp_repo, config, target=REL, aws=None, evidence_file=changed, now=NOW)
    assert r.status == "PROPOSED"
    assert [(a.section, a.entry) for a in r.additions] == [("must_allow", "10.0.6.20/32 → 22/tcp")]
    assert [(x.section, x.entry) for x in r.removals] == [("must_allow", "10.0.5.9/32 → 22/tcp")]
    # Never removed silently: the unseen entry is still in must_allow, flagged.
    proposed = load_contract_text(r.proposed)
    allow = {x.cidr: x for x in proposed.must_allow}
    assert "10.0.5.9/32" in allow and "not seen" in (allow["10.0.5.9/32"].reason or "")
    assert "10.0.6.20/32" in allow
    assert proposed.status == "draft" and proposed.approved_by is None
    assert proposed.must_deny == load_contract(path).must_deny  # type: ignore[union-attr]
    assert path.read_text(encoding="utf-8") == before  # the approved file is never edited


def load_contract_text(text: str | None) -> Any:
    from posturanet.models import BehaviorContract

    assert text is not None
    return BehaviorContract.model_validate(YAML(typ="safe").load(text))


def test_refresh_fails_closed_on_weak_evidence(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path, tmp_path: Path
) -> None:
    _approved_sg(tmp_repo, flows_path, sg_finding_path)
    data = json.loads(flows_path.read_text(encoding="utf-8"))
    data["window"]["from"] = "2026-10-25T00:00:00Z"  # 4 days: confidence low
    data["records"] = [r for r in data["records"] if r["hour"] >= "2026-10-25"]
    short = tmp_path / "short.json"
    short.write_text(json.dumps(data), encoding="utf-8")
    config, _ = load_config(tmp_repo)
    [r] = refresh(tmp_repo, config, target=ADDRESS, aws=None, evidence_file=short, now=NOW)
    assert r.status == "UNKNOWN" and r.proposed is None
    assert "needs" in r.reasons[0]


def test_refresh_skips_drafts_and_refuses_shared_evidence(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    config, _ = load_config(tmp_repo)
    run_fix(str(sg_finding_path), tmp_repo, config, Context(mode="check", evidence=FileSource(flows_path), terraform=FakeTerraform()))  # fmt: skip
    [r] = refresh(tmp_repo, config, target=ADDRESS, aws=None, evidence_file=flows_path, now=NOW)
    assert r.status == "SKIPPED"
    (tmp_repo / "posturanet/contracts/other.yaml").write_text(
        (tmp_repo / REL).read_text(encoding="utf-8").replace(ADDRESS, "aws_security_group.x"),
        encoding="utf-8",
    )
    from posturanet.errors import StageStop

    with pytest.raises(StageStop, match="one resource's evidence"):
        refresh(tmp_repo, config, target=None, aws=None, evidence_file=flows_path, now=NOW)


def test_refresh_unknown_resource_target(tmp_repo: Path) -> None:
    from posturanet.errors import StageStop

    config, _ = load_config(tmp_repo)
    with pytest.raises(StageStop, match="no contract"):
        refresh(tmp_repo, config, target="aws_security_group.nope", aws=None)


# --- refresh: IAM and S3


def _iam_contract(repo: Path) -> Path:
    c = IamContract(
        resource="aws_iam_policy.app",
        account="123456789012",
        policy_arn="arn:aws:iam::123456789012:policy/app",
        observed=ObservedMeta(
            source="iam_last_accessed",
            window=ObservedWindow(start=date(2025, 6, 1), end=date(2026, 9, 1), days=457),
            confidence=Confidence.HIGH,
        ),
        must_allow=[
            IamAllowed(action="ec2:DescribeInstances", last_seen=date(2026, 8, 1)),
            IamAllowed(action="ec2:RunInstances", last_seen=date(2025, 7, 1)),
            IamAllowed(action="ec2:StopInstances", source="human", owner="@ops"),
            IamAllowed(action="logs:CreateLogStream", last_seen=date(2026, 8, 1)),
        ],
        status="approved",
        approved_by="@pat",
    )
    path = repo / "posturanet/contracts/aws_iam_policy.app.yaml"
    iamcontract.write(path, c)
    return path


def test_refresh_iam_adds_used_and_flags_unused_but_never_human(tmp_repo: Path) -> None:
    _iam_contract(tmp_repo)
    config, _ = load_config(tmp_repo)
    [r] = refresh(
        tmp_repo,
        config,
        target="aws_iam_policy.app",
        aws=None,
        evidence_file=FIXTURES / "iam" / "app.json",
        now=NOW,
    )
    assert r.status == "PROPOSED"
    assert [a.entry for a in r.additions] == ["ec2:DescribeVolumes"]
    assert [x.entry for x in r.removals] == ["ec2:RunInstances"]  # the human one stays silent
    proposed = IamContract.model_validate(YAML(typ="safe").load(r.proposed))
    assert {a.action for a in proposed.must_allow} >= {"ec2:RunInstances", "ec2:DescribeVolumes"}
    assert any("ec2:RunInstances" in n for n in proposed.needs_review)


def _s3_fixture(tmp_path: Path, requesters: list[str]) -> Path:
    days = [f"2026-08-{d:02d}" for d in range(1, 32)] + [f"2026-09-{d:02d}" for d in range(1, 31)]
    days += [f"2026-10-{d:02d}" for d in range(1, 30)]
    data = {
        "account": "123456789012",
        "window": {"from": "2026-08-01", "to": "2026-10-30"},
        "buckets": [
            {
                "name": "acme-assets",
                "policy_public": False,
                "acl_public": False,
                "acls_enabled": True,
                "website": False,
                "logging": True,
                "missing_days": [],
                "requests": [
                    {
                        "requester": who,
                        "operation": "REST.GET.OBJECT",
                        "status": 200,
                        "day": d,
                        "n": 5,
                    }
                    for who in requesters
                    for d in days
                ],
            }
        ],
    }
    path = tmp_path / "s3.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _s3_contract(repo: Path, keep: list[str]) -> None:
    c = S3Contract(
        resource="aws_s3_bucket_public_access_block.assets",
        account="123456789012",
        observed=ObservedMeta(
            source="s3_access_logs",
            window=ObservedWindow(start=date(2026, 5, 1), end=date(2026, 8, 1), days=90),
            confidence=Confidence.HIGH,
        ),
        exposure={
            "acme-assets": Exposure(
                policy_public=False, acl_public=False, acls_enabled=True, website=False
            )
        },  # noqa: E501
        must_keep=[
            S3Use(
                requester=k,
                kind="in_account",
                operations=["REST.GET.OBJECT"],
                count=1,
                last_seen=date(2026, 7, 1),
            )  # noqa: E501
            for k in keep
        ],
        status="approved",
    )
    s3contract.write(repo / "posturanet/contracts/assets.yaml", c)


ROLE = "arn:aws:sts::123456789012:assumed-role/{}/i-0abc"


def test_refresh_s3_compares_requesters(tmp_repo: Path, tmp_path: Path) -> None:
    _s3_contract(tmp_repo, [ROLE.format("app"), ROLE.format("batch")])
    ev = _s3_fixture(tmp_path, [ROLE.format("app"), ROLE.format("etl")])
    config, _ = load_config(tmp_repo)
    [r] = refresh(tmp_repo, config, target="assets.yaml", aws=None, evidence_file=ev, now=NOW)
    assert r.status == "PROPOSED", r
    assert [a.entry for a in r.additions] == [ROLE.format("etl")]
    assert [x.entry for x in r.removals] == [ROLE.format("batch")]
    assert ROLE.format("batch") in (r.proposed or "")  # flagged, not removed


def test_refresh_s3_private_bucket_is_skipped(tmp_repo: Path) -> None:
    _s3_contract(tmp_repo, [ROLE.format("app")])
    data = json.loads((FIXTURES / "s3" / "reports_private.json").read_text(encoding="utf-8"))
    data["buckets"][0]["name"] = "acme-assets"
    ev = tmp_repo / "ev.json"
    ev.write_text(json.dumps(data), encoding="utf-8")
    config, _ = load_config(tmp_repo)
    [r] = refresh(tmp_repo, config, target="assets.yaml", aws=None, evidence_file=ev, now=NOW)
    assert r.status == "SKIPPED" and "must_keep stays" in r.reasons[0]


# --- drift: check --live


def test_live_sg_passes_when_deployed_matches(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _approved_sg(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)
    aws = _aws({"ec2": _sg_groups(_ssh(*KEPT))})
    result = check_live(tmp_repo, config, aws)
    assert result.status == "PASS", result.to_dict()
    assert result.summary == "PASS · 1 contract checked against the live resources"


def test_live_sg_blocks_console_reopen(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _approved_sg(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)
    aws = _aws({"ec2": _sg_groups(_ssh(*KEPT, "0.0.0.0/0"))})
    result = check_live(tmp_repo, config, aws)
    assert result.status == "BLOCK"
    [r] = result.results
    assert r.reasons[0].startswith("breaks must_deny: 0.0.0.0/0 → 22/tcp")
    assert r.violations[0].contract_line is not None
    assert r.caused_by == f"live ingress on {SG_ID}"
    text = render_gate(result, width=None)
    assert "BLOCK · 1 live resource breaks its contract" in text
    assert "restore it from code (re-apply)" in text
    assert text.endswith("Stopped. Restore the resource or update its contract.\n")


def test_live_sg_removed_user_blocks_and_prefix_list_is_unknown(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _approved_sg(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)
    aws = _aws({"ec2": _sg_groups(_ssh(*KEPT[:3]))})
    assert check_live(tmp_repo, config, aws).status == "BLOCK"
    perm = {**_ssh(*KEPT), "PrefixListIds": [{"PrefixListId": "pl-0123"}]}
    result = check_live(tmp_repo, config, _aws({"ec2": _sg_groups(perm)}))
    assert result.status == "UNKNOWN"  # a prefix list may hold 0.0.0.0/0: never PASS on it
    perm = {**_ssh(*KEPT[:3]), "UserIdGroupPairs": [{"GroupId": "sg-0peer"}]}
    result = check_live(tmp_repo, config, _aws({"ec2": _sg_groups(perm)}))
    assert result.status == "UNKNOWN"


def test_live_read_errors_and_other_accounts_are_unknown(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _approved_sg(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)

    def boom(**_: Any) -> Any:
        raise _ClientError("UnauthorizedOperation")

    result = check_live(tmp_repo, config, _aws({"ec2": _Client(describe_security_groups=boom)}))
    assert result.status == "UNKNOWN"
    assert "UnauthorizedOperation" in result.results[0].reasons[0]
    c = load_contract(tmp_repo / REL)
    assert c is not None
    write_contract(tmp_repo / REL, c.model_copy(update={"account": "123456789012"}))
    result = check_live(tmp_repo, config, _aws({"ec2": _sg_groups(_ssh(*KEPT))}, "210987654321"))
    assert result.status == "UNKNOWN" and "210987654321" in result.results[0].reasons[0]


def _s3_client(conf: dict[str, bool] | None, public: bool) -> _Client:
    def pab(Bucket: str) -> Any:  # noqa: N803 (boto3 casing)
        if conf is None:
            raise _ClientError("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": conf}

    def status(Bucket: str) -> Any:  # noqa: N803 (boto3 casing)
        return {"PolicyStatus": {"IsPublic": public}}

    return _Client(get_public_access_block=pab, get_bucket_policy_status=status)


ALL_ON = dict.fromkeys(
    ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"], True
)


def test_live_s3(tmp_repo: Path) -> None:
    _s3_contract(tmp_repo, [ROLE.format("app")])
    config, _ = load_config(tmp_repo)
    assert check_live(tmp_repo, config, _aws({"s3": _s3_client(ALL_ON, False)})).status == "PASS"
    result = check_live(tmp_repo, config, _aws({"s3": _s3_client(None, False)}))
    assert result.status == "BLOCK" and "is off on acme-assets" in result.results[0].reasons[0]
    off = {**ALL_ON, "RestrictPublicBuckets": False}
    assert check_live(tmp_repo, config, _aws({"s3": _s3_client(off, False)})).status == "BLOCK"
    result = check_live(tmp_repo, config, _aws({"s3": _s3_client(ALL_ON, True)}))
    assert result.status == "BLOCK" and "policy is public" in result.results[0].reasons[0]


def _iam_client(doc: Any) -> _Client:
    return _Client(
        get_policy=lambda PolicyArn: {"Policy": {"DefaultVersionId": "v3"}},  # noqa: N803
        get_policy_version=lambda PolicyArn, VersionId: {"PolicyVersion": {"Document": doc}},  # noqa: N803
    )


def test_live_iam(tmp_repo: Path) -> None:
    path = _iam_contract(tmp_repo)
    c = iamcontract.load(path)
    assert c is not None
    iamcontract.write(path, c.model_copy(update={"must_remove": ["ec2:*"]}))
    config, _ = load_config(tmp_repo)
    actions = [
        "ec2:DescribeInstances",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "logs:CreateLogStream",
    ]  # noqa: E501
    good = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    }  # noqa: E501
    assert check_live(tmp_repo, config, _aws({"iam": _iam_client(good)})).status == "PASS"
    encoded = quote(json.dumps(good))
    assert check_live(tmp_repo, config, _aws({"iam": _iam_client(encoded)})).status == "PASS"
    bad = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["ec2:*", "logs:*"], "Resource": "*"}],
    }  # noqa: E501
    result = check_live(tmp_repo, config, _aws({"iam": _iam_client(bad)}))
    assert result.status == "BLOCK"
    assert any("must_remove: ec2:*" in x for x in result.results[0].reasons)


# --- delivery


def test_refresh_pr_is_opened_once_then_unchanged(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path, tmp_path: Path
) -> None:
    path = _approved_sg(tmp_repo, flows_path, sg_finding_path)
    changed = _flows(flows_path, tmp_path / "f.json", add="10.0.6.20")
    config, _ = load_config(tmp_repo)
    [r] = refresh(tmp_repo, config, target=ADDRESS, aws=None, evidence_file=changed, now=NOW)
    fake = FakeGitHub({REL: path.read_text(encoding="utf-8")})
    gh = GitHub("t", "acme/infra", client=fake.client())
    first = deliver_refresh(gh, r, tmp_repo, base="main", max_open=5)
    assert first.action == "opened" and first.branch.startswith("posturanet/contract/")
    assert fake.files[(first.branch, REL)] == r.proposed
    body = fake.prs[0]["body"]
    assert "Not seen in the window" not in body and "10.0.6.20/32 → 22/tcp" in body
    second = deliver_refresh(gh, r, tmp_repo, base="main", max_open=5)
    assert second.action == "unchanged" and len(fake.prs) == 1  # FR-28


def test_refresh_pr_respects_max_open(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path, tmp_path: Path
) -> None:
    from posturanet.errors import StageStop

    path = _approved_sg(tmp_repo, flows_path, sg_finding_path)
    changed = _flows(flows_path, tmp_path / "f.json", add="10.0.6.20")
    config, _ = load_config(tmp_repo)
    [r] = refresh(tmp_repo, config, target=ADDRESS, aws=None, evidence_file=changed, now=NOW)
    busy = [
        {
            "number": n,
            "state": "open",
            "labels": [{"name": "posturanet"}],
            "body": "",
            "head": {"ref": "x"},
            "html_url": "u",
        }  # noqa: E501
        for n in (1, 2)
    ]
    fake = FakeGitHub({REL: path.read_text(encoding="utf-8")}, busy)
    with pytest.raises(StageStop, match="limit 2"):
        deliver_refresh(
            GitHub("t", "acme/infra", client=fake.client()), r, tmp_repo, base="main", max_open=2
        )  # noqa: E501


class _Issues:
    def __init__(self) -> None:
        self.issues: list[dict[str, Any]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        if request.method == "GET":
            return httpx.Response(200, json=[i for i in self.issues if i["state"] == "open"])
        if request.method == "POST":
            n = len(self.issues) + 1
            self.issues.append({"number": n, "state": "open", "html_url": f"u/{n}", **body})
            return httpx.Response(201, json=self.issues[-1])
        n = int(request.url.path.rsplit("/", 1)[1])
        self.issues[n - 1].update(body)
        return httpx.Response(200, json=self.issues[n - 1])


def test_drift_issue_opens_updates_and_closes(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    _approved_sg(tmp_repo, flows_path, sg_finding_path)
    config, _ = load_config(tmp_repo)
    fake = _Issues()
    gh = GitHub(
        "t",
        "acme/infra",
        client=httpx.Client(
            base_url="https://api.github.com", transport=httpx.MockTransport(fake.handler)
        ),
    )  # noqa: E501
    ok = check_live(tmp_repo, config, _aws({"ec2": _sg_groups(_ssh(*KEPT))})).results[0]
    assert deliver_drift(gh, ok) is None and not fake.issues  # nothing to report, nothing opened
    bad = check_live(tmp_repo, config, _aws({"ec2": _sg_groups(_ssh(*KEPT, "0.0.0.0/0"))}))
    url = deliver_drift(gh, bad.results[0])
    assert url == "u/1" and fake.issues[0]["body"].startswith(drift_marker(ADDRESS))
    assert "breaks its behavior contract" in fake.issues[0]["body"]
    deliver_drift(gh, bad.results[0])
    assert len(fake.issues) == 1  # one issue per resource
    deliver_drift(gh, ok)
    assert fake.issues[0]["state"] == "closed"


# --- CLI and output (design system section 4.8)


def test_cli_refresh_and_live_usage(
    tmp_repo: Path, flows_path: Path, sg_finding_path: Path
) -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["contract", "refresh", "--repo", str(tmp_repo)])
    assert res.exit_code == 2
    res = runner.invoke(app, ["contract", "check", "--live", "--source", "--repo", str(tmp_repo)])
    assert res.exit_code == 2 and "exactly one of --plan, --source or --live" in res.output
    _approved_sg(tmp_repo, flows_path, sg_finding_path)
    args = [
        "contract",
        "refresh",
        ADDRESS,
        "--repo",
        str(tmp_repo),
        "--evidence-file",
        str(flows_path),
    ]  # noqa: E501
    res = runner.invoke(app, [*args, "--format", "json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["status"] == "PASS"


def test_render_refresh_snapshot() -> None:
    from posturanet.models.living import ContractRefresh, RefreshChange

    results = [
        ContractRefresh(
            resource=ADDRESS,
            contract_file=REL,
            kind="network",
            status="PROPOSED",
            evidence="flow logs file · 89 days · confidence high",
            additions=[
                RefreshChange(
                    section="must_allow",
                    entry="10.0.6.20/32 → 22/tcp",
                    detail="1,204 conns · daily",
                )
            ],  # noqa: E501
            removals=[
                RefreshChange(
                    section="must_allow", entry="10.0.5.9/32 → 22/tcp", detail="not seen in 89 days"
                )
            ],  # noqa: E501
            proposed="x",
        ),
        ContractRefresh(
            resource="aws_iam_policy.app",
            contract_file="posturanet/contracts/aws_iam_policy.app.yaml",
            kind="iam",
            status="UNKNOWN",
            reasons=["confidence low; needs medium to propose changes (the same rule as fix)"],
        ),
    ]
    text = render_refresh(results, open_pr=False, ascii_mode=True)
    expected = """\
+  PosturaNet {v} - contract refresh - 2 contracts
|
*  UNKNOWN - 1 with proposed changes - 1 unknown
|
o  ! module.bastion.aws_security_group.this --------------------------------------+
|                                                                                 |
|  flow logs file - 89 days - confidence high                                     |
|  + must_allow    10.0.6.20/32 -> 22/tcp    1,204 conns - daily                  |
|  ! must_allow    10.0.5.9/32 -> 22/tcp     not seen in 89 days (flagged, kept)  |
|                                                                                 |
+---------------------------------------------------------------------------------+
|
o  ? aws_iam_policy.app ---------------------------------------------------+
|                                                                          |
|  confidence low; needs medium to propose changes (the same rule as fix)  |
|                                                                          |
+--------------------------------------------------------------------------+
|
+  Stopped where the evidence was weak or unreadable. Nothing was changed there.
"""
    from posturanet import __version__

    assert text == expected.format(v=__version__)


def test_live_contract_loads_via_gate(tmp_repo: Path) -> None:
    _s3_contract(tmp_repo, [])
    loaded = _load(tmp_repo / "posturanet/contracts/assets.yaml", tmp_repo)
    assert loaded is not None and loaded.contract.kind == "s3_public"
