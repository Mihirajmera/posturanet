"""Living contracts (R11): keep approved contracts true over time, in the customer's CI.

- `refresh` (FR-52): re-collect evidence with the same read-only collectors and window as
  `fix`, compare it with each approved contract (`contracts/refresh.py`), and propose an
  update as a PR a person approves. The contract file in the checkout is never edited.
- `check_live` (FR-53): read the deployed resource read-only and judge it against its
  contract with the same rules as `contract check`. Someone reopening 0.0.0.0/0 in the
  console is a BLOCK; anything PosturaNet can't read or judge is UNKNOWN, never PASS.
- `deliver_refresh` / `deliver_drift` (FR-54): one PR per contract update and one issue per
  drifted resource, found again by marker so a scheduled run updates instead of duplicating.

AWS calls are the existing allowlisted reads: ec2:DescribeSecurityGroups,
s3:GetBucketPublicAccessBlock, s3:GetBucketPolicyStatus, iam:GetPolicy,
iam:GetPolicyVersion, cloudformation:DescribeStackResources, sts:GetCallerIdentity.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from posturanet import cdk, cfn
from posturanet.aws.session import ClientFactory
from posturanet.contracts import refresh as rf
from posturanet.deliver.github import Delivery, GitHub, PullRequest, push_pr
from posturanet.deliver.idempotency import markers
from posturanet.errors import StageStop
from posturanet.evidence import FileSource, FlowSource, LogsInsightsSource, collect
from posturanet.gate import (
    ContractResult,
    GateResult,
    Violation,
    _all_contracts,
    _finish,
    _judge,
    _Loaded,
    _overall,
)
from posturanet.iamfix import gate as iam_gate
from posturanet.iamfix.evidence import FileIamSource, IamSource, LiveIamSource
from posturanet.locate import load_repo_state
from posturanet.locate.backend import boto3_s3_fetch
from posturanet.locate.tfstate import attributes_of
from posturanet.models import BehaviorContract, Confidence, Config
from posturanet.models.iam import IamContract
from posturanet.models.living import ContractRefresh
from posturanet.models.s3 import S3Contract
from posturanet.s3fix import FLAG_NAMES
from posturanet.s3fix import gate as s3_gate
from posturanet.s3fix.evidence import FileS3Source, LiveS3Source, S3Source, analyze
from posturanet.synth.sg_rules import Rule, norm_proto

_PAB = {
    "block_public_acls": "BlockPublicAcls",
    "block_public_policy": "BlockPublicPolicy",
    "ignore_public_acls": "IgnorePublicAcls",
    "restrict_public_buckets": "RestrictPublicBuckets",
}


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", "")) or exc.__class__.__name__
    return exc.__class__.__name__


def select(repo: Path, config: Config, target: str | None) -> list[_Loaded]:
    """Contracts to work on: one by resource address or file path, or all of them."""
    contracts = _all_contracts(repo, config)
    if target is None:
        return contracts
    name = Path(target).name
    hits = [
        c for c in contracts if target in (c.contract.resource, c.rel) or name == Path(c.rel).name
    ]
    if not hits:
        raise StageStop(
            "contract",
            f"no contract for {target} in {config.contracts.dir}/",
            ["pass the contract's resource address or file, or use --all"],
        )
    return hits


# --- contract -> deployed resource


def group_id(
    address: str, repo: Path, config: Config, state_path: Path | None, aws: ClientFactory | None
) -> str:
    """The security group id behind a `network` contract, read-only. StageStop if unknown."""
    stack_logical = cfn.split_address(address) or cdk.split_address(address)
    if stack_logical is not None:
        stack, logical = stack_logical
        if aws is None:
            raise StageStop("contract", f"{address}: needs AWS to find the stack's group id")
        rows = aws("cloudformation").describe_stack_resources(
            StackName=stack, LogicalResourceId=logical
        )["StackResources"]
        ids = [r["PhysicalResourceId"] for r in rows if r.get("PhysicalResourceId")]
        if len(ids) != 1:
            raise StageStop("contract", f"stack {stack} has no deployed {logical}", unknown=True)
        return str(ids[0])
    if address.startswith("pulumi."):
        raise StageStop(
            "contract",
            f"{address}: Pulumi security groups aren't read live yet",
            ["check this group with `posturanet contract check --source`"],
            unknown=True,
        )
    s3_fetch = boto3_s3_fetch(aws) if aws is not None else None
    state, _ = load_repo_state(repo, config, state_path, s3_fetch)
    attrs = attributes_of(state, address)
    if not attrs or not attrs.get("id"):
        raise StageStop(
            "contract",
            f"{address} is not in the Terraform state",
            ["apply the change that creates it, or delete the contract if it was removed"],
            unknown=True,
        )
    return str(attrs["id"])


def _account_scope(c: S3Contract) -> bool:
    return "account_public_access_block" in c.resource


# --- drift: the live resource against its contract (FR-53)


def live_rules(groups: list[dict[str, Any]]) -> tuple[list[Rule], int, int]:
    """(CIDR rules, security-group sources, prefix-list sources) of described groups."""
    rules: list[Rule] = []
    peers = lists = 0
    for g in groups:
        for p in g.get("IpPermissions", []):
            proto = norm_proto(p.get("IpProtocol", ""))
            lo, hi = int(p.get("FromPort", -1)), int(p.get("ToPort", -1))
            cidrs = [x["CidrIp"] for x in p.get("IpRanges", [])]
            cidrs += [x["CidrIpv6"] for x in p.get("Ipv6Ranges", [])]
            rules += [Rule(c, lo, hi, proto) for c in cidrs]
            peers += len(p.get("UserIdGroupPairs", []))
            lists += len(p.get("PrefixListIds", []))
    return rules, peers, lists


def judge_sg(loaded: _Loaded, gid: str, groups: list[dict[str, Any]]) -> ContractResult:
    c = loaded.contract
    assert isinstance(c, BehaviorContract)
    result = ContractResult(c.resource, loaded.rel, "PASS", live=gid)
    rules, peers, lists = live_rules(groups)
    result = _judge(result, c, rules, loaded.text)
    if not peers and not lists:
        return result
    # Sources that aren't CIDRs may admit a must_allow address (an instance in a peer group,
    # a prefix-list entry) and a prefix list may hold 0.0.0.0/0: say so, never PASS on it.
    unknowns: list[str] = []
    keep: list[Violation] = []
    for v in result.violations:
        if v.message.startswith("breaks must_allow") and (peers or lists):
            unknowns.append(
                v.message.replace("breaks must_allow:", "must_allow not admitted by a CIDR:")
                + " (security-group or prefix-list sources aren't expanded)"
            )
        else:
            keep.append(v)
    if lists and c.must_deny and not keep:
        unknowns.append(f"{lists} prefix-list source(s) aren't expanded; they may admit must_deny")
    result.violations = keep
    result.reasons = [*(v.message for v in keep), *unknowns]
    result.status = "BLOCK" if keep else "UNKNOWN" if unknowns else "PASS"
    return result


def _sg_live(
    loaded: _Loaded, repo: Path, config: Config, state_path: Path | None, aws: ClientFactory
) -> ContractResult:
    gid = group_id(loaded.contract.resource, repo, config, state_path, aws)
    groups = aws("ec2").describe_security_groups(GroupIds=[gid])["SecurityGroups"]
    return judge_sg(loaded, gid, groups)


def _s3_live(loaded: _Loaded, aws: ClientFactory) -> ContractResult:
    c = loaded.contract
    assert isinstance(c, S3Contract)
    buckets = sorted(c.exposure)
    result = ContractResult(
        c.resource, loaded.rel, "PASS", subject="public access", live=", ".join(buckets)
    )
    violations: list[str] = []
    unknowns: list[str] = []
    s3 = aws("s3")
    if _account_scope(c):
        unknowns.append(
            "the account's Block Public Access isn't read live (it needs "
            "s3:GetAccountPublicAccessBlock, not on the read-only allowlist)"
        )
    for b in buckets:
        if not _account_scope(c):
            try:
                conf = s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"]
            except Exception as exc:  # botocore ClientError; boto3 is only imported in aws/
                if _code(exc) != "NoSuchPublicAccessBlockConfiguration":
                    unknowns.append(f"reading {b}'s Block Public Access failed ({_code(exc)})")
                    conf = None
                else:
                    conf = {}  # no configuration: every flag is off
            if conf is not None:
                v, _ = s3_gate.judge_flags(c, {f: bool(conf.get(_PAB[f])) for f in FLAG_NAMES})
                violations += [x.replace(" is off", f" is off on {b}") for x in v]
        try:
            public = bool(s3.get_bucket_policy_status(Bucket=b)["PolicyStatus"]["IsPublic"])
        except Exception as exc:  # botocore ClientError; boto3 is only imported in aws/
            if _code(exc) != "NoSuchBucketPolicy":
                unknowns.append(f"reading {b}'s policy status failed ({_code(exc)})")
            public = False
        if public:
            draft = "" if c.status == "approved" else " (draft contract)"
            violations.append(f"breaks must_block: the {b} bucket policy is public{draft}")
    result = _finish(result, loaded, violations, unknowns, ["must_block"] * len(violations))
    if c.must_keep:  # stated, not an UNKNOWN: Block Public Access never denies a named grant
        result.reasons.append("must_keep requesters aren't checked live (needs the policy text)")
    return result


def _policy_doc(raw: Any) -> dict[str, Any]:
    # IAM returns the document URL-encoded; boto3 usually decodes it already
    doc = json.loads(unquote(raw)) if isinstance(raw, str) else raw
    if not isinstance(doc, dict):
        raise ValueError("policy document is not a JSON object")
    return doc


def _iam_live(loaded: _Loaded, aws: ClientFactory) -> ContractResult:
    c = loaded.contract
    assert isinstance(c, IamContract)
    result = ContractResult(c.resource, loaded.rel, "PASS", subject="policy", live=c.policy_arn)
    iam = aws("iam")
    version = iam.get_policy(PolicyArn=c.policy_arn)["Policy"]["DefaultVersionId"]
    raw = iam.get_policy_version(PolicyArn=c.policy_arn, VersionId=version)["PolicyVersion"]
    try:
        doc = _policy_doc(raw["Document"])
    except (ValueError, KeyError) as exc:
        return _finish(result, loaded, [], [f"the live policy can't be read: {exc}"], [])
    violations, unknowns, needles = iam_gate.judge(c, doc)
    return _finish(result, loaded, violations, unknowns, needles)


def check_live(
    repo: Path,
    config: Config,
    aws: ClientFactory,
    target: str | None = None,
    state_path: Path | None = None,
) -> GateResult:
    """Judge every selected contract against the deployed resource (read-only)."""
    caller: str | None = None
    try:
        caller = str(aws("sts").get_caller_identity()["Account"])
    except Exception:  # botocore errors; the resource reads below fail closed on their own
        caller = None
    results: list[ContractResult] = []
    for loaded in select(repo, config, target):
        c = loaded.contract
        kind = {"network": "ingress", "s3_public": "public access", "iam": "policy"}[c.kind]
        if c.account and caller and c.account != caller:
            results.append(
                ContractResult(
                    c.resource,
                    loaded.rel,
                    "UNKNOWN",
                    [f"contract is for account {c.account}; the role reads {caller}"],
                    subject=kind,
                )
            )
            continue
        try:
            if isinstance(c, BehaviorContract):
                results.append(_sg_live(loaded, repo, config, state_path, aws))
            elif isinstance(c, S3Contract):
                results.append(_s3_live(loaded, aws))
            else:
                results.append(_iam_live(loaded, aws))
        except StageStop as stop:
            results.append(
                ContractResult(c.resource, loaded.rel, "UNKNOWN", [stop.reason], subject=kind)
            )
        except Exception as exc:  # botocore ClientError; boto3 is only imported in aws/
            results.append(
                ContractResult(
                    c.resource,
                    loaded.rel,
                    "UNKNOWN",
                    [f"reading the live {kind} failed ({_code(exc)})"],
                    subject=kind,
                )
            )
    return GateResult(_overall(results), results, "live")


# --- refresh: fresh evidence against each approved contract (FR-52)


def refresh(
    repo: Path,
    config: Config,
    *,
    target: str | None,
    aws: ClientFactory | None,
    evidence_file: Path | None = None,
    window_days: int | None = None,
    state_path: Path | None = None,
    now: datetime | None = None,
) -> list[ContractRefresh]:
    """One result per selected contract. A contract whose evidence can't be read is UNKNOWN;
    it never stops the others."""
    now = now or datetime.now(UTC)
    window = window_days or config.evidence.window_days
    minimum = Confidence(config.evidence.min_confidence_for_pr)
    selected = select(repo, config, target)
    if evidence_file is not None and len(selected) != 1:
        # FR-12: one resource's evidence is never reused for another
        raise StageStop(
            "evidence",
            "--evidence-file holds one resource's evidence; name one contract",
            ["posturanet contract refresh <resource> --evidence-file <file>"],
        )
    out: list[ContractRefresh] = []
    for loaded in selected:
        c = loaded.contract
        if c.status != "approved":
            out.append(rf.skipped_draft(c, loaded.rel))
            continue
        try:
            out.append(
                _refresh_one(
                    loaded, repo, config, aws, evidence_file, window, minimum, state_path, now
                )
            )
        except StageStop as stop:
            out.append(
                ContractRefresh(
                    resource=c.resource,
                    contract_file=loaded.rel,
                    kind=c.kind,
                    status="UNKNOWN",
                    reasons=[stop.reason, *stop.next_steps[:1]],
                )
            )
        except Exception as exc:  # botocore ClientError; boto3 is only imported in aws/
            out.append(
                ContractRefresh(
                    resource=c.resource,
                    contract_file=loaded.rel,
                    kind=c.kind,
                    status="UNKNOWN",
                    reasons=[f"reading the evidence failed ({_code(exc)})"],
                )
            )
    return out


def _flow_source(config: Config, aws: ClientFactory | None) -> FlowSource:
    group = config.evidence.flow_logs.log_group
    if not group:
        raise StageStop(
            "evidence",
            "evidence.flow_logs.log_group is not set",
            ["set evidence.flow_logs.log_group in .posturanet.yml"],
        )
    if aws is None:
        raise StageStop("evidence", "no AWS access configured")
    return LogsInsightsSource(aws("ec2"), aws("logs"), group)


def _refresh_one(
    loaded: _Loaded,
    repo: Path,
    config: Config,
    aws: ClientFactory | None,
    evidence_file: Path | None,
    window: int,
    minimum: Confidence,
    state_path: Path | None,
    now: datetime,
) -> ContractRefresh:
    c, rel, today = loaded.contract, loaded.rel, now.date()
    if isinstance(c, BehaviorContract):
        source = FileSource(evidence_file) if evidence_file else _flow_source(config, aws)
        gid = group_id(c.resource, repo, config, state_path, aws)
        obs = collect(source, gid, c.resource, now=now, window_days=window)
        return rf.network(c, obs, rel, minimum)
    if isinstance(c, IamContract):
        iam_source: IamSource
        if evidence_file is not None:
            iam_source = FileIamSource(evidence_file)
        elif aws is not None:
            iam_source = LiveIamSource(aws("iam"))
        else:
            raise StageStop("evidence", "no AWS access configured")
        return rf.iam(c, iam_source.policy(c.policy_arn, today), rel, minimum, today)
    s3_source: S3Source
    if evidence_file is not None:
        s3_source = FileS3Source(evidence_file)
    elif aws is not None:
        s3_source = LiveS3Source(aws("s3"), aws("cloudfront"), c.account)
    else:
        raise StageStop("evidence", "no AWS access configured")
    start = today - timedelta(days=window)
    if _account_scope(c):
        facts, scope = s3_source.account(start, today), "account"
    else:
        if len(c.exposure) != 1:
            raise StageStop("evidence", f"{rel} names {len(c.exposure)} buckets; expected one")
        facts, scope = s3_source.bucket(next(iter(c.exposure)), start, today), "bucket"
    ev = analyze(facts, scope=scope, source=s3_source.source, reviewed=frozenset())
    return rf.s3(c, ev, rel, minimum, today)


# --- delivery: one PR per contract update, one issue per drifted resource (FR-54)

LABELS = ["posturanet", "contract-update"]
DRIFT_LABELS = ["posturanet", "drift"]


def _refresh_issue(resource: str) -> str:
    return f"contract-refresh@{resource}"


def refresh_body(r: ContractRefresh) -> str:
    """PR body (design system section 6.4)."""
    assert r.proposed is not None
    key = hashlib.sha256(r.proposed.encode("utf-8")).hexdigest()
    lines = [
        markers(key, _refresh_issue(r.resource)),
        f"**PosturaNet** re-read the evidence for `{r.resource}` and proposes an update to its "
        "behavior contract. Nothing in AWS changed; merging this only changes what future "
        "checks enforce.",
        "",
        "| | |",
        "|---|---|",
        f"| Contract | `{r.contract_file}` |",
        f"| Evidence | {r.evidence} |",
        "",
    ]
    if r.additions:
        lines += ["### New since approval (proposed additions)", "", "| Section | Entry | Seen |"]
        lines += ["|---|---|---|"]
        lines += [f"| {a.section} | `{a.entry}` | {a.detail} |" for a in r.additions]
        lines.append("")
    if r.removals:
        lines += [
            "### Not seen in the window (flagged, not removed)",
            "",
            "Rare jobs (a quarterly drill, a yearly audit) look exactly like this. PosturaNet "
            "keeps these entries; delete one by hand only if its owner confirms it is retired.",
            "",
            "| Section | Entry | Why flagged |",
            "|---|---|---|",
        ]
        lines += [f"| {x.section} | `{x.entry}` | {x.detail} |" for x in r.removals]
        lines.append("")
    lines += [
        "### Before you merge",
        "- [ ] Confirm each new entry with its owner (add `owner:` / `ref:`).",
        "- [ ] Decide on each flagged entry: keep it, or delete it if retired.",
        "- [ ] Set `status: approved`, `approved_by` and `approved_at`. Until then the contract is "
        "a draft; checks still enforce every entry in it.",
        "",
        "<sub>PosturaNet · evidence describes the observed window; behavior rarer than the "
        "window is not observed.</sub>",
    ]
    return "\n".join(lines) + "\n"


def deliver_refresh(
    gh: GitHub, r: ContractRefresh, repo: Path, *, base: str, max_open: int
) -> Delivery:
    assert r.proposed is not None
    key = hashlib.sha256(r.proposed.encode("utf-8")).hexdigest()
    short = Path(r.contract_file).stem.replace("_", "-").lower()[:40]
    original = (repo / r.contract_file).read_text(encoding="utf-8")
    title = f"PosturaNet: update contract for {Path(r.contract_file).stem}"[:72]
    return push_pr(
        gh,
        PullRequest(
            finding_id=_refresh_issue(r.resource),
            issue=_refresh_issue(r.resource),
            key=key,
            branch=f"posturanet/contract/{short}-{key[:8]}",
            title=title,
            body=refresh_body(r),
            labels=LABELS,
            writes=[(r.contract_file, r.proposed, f"docs(contract): refresh {r.resource}")],
        ),
        base=base,
        max_open=max_open,
        local_originals={r.contract_file: original},
    )


def drift_marker(resource: str) -> str:
    return f"<!-- posturanet:drift={hashlib.sha256(resource.encode()).hexdigest()[:16]} -->"


def drift_body(r: ContractResult) -> str:
    """Issue body for a live resource that breaks its contract (design system section 7.1)."""
    sym = {"BLOCK": "✗", "UNKNOWN": "?"}.get(r.status, "✓")
    lines = [
        drift_marker(r.address),
        f"**PosturaNet** read `{r.address}` live and it "
        + (
            "**breaks its behavior contract**."
            if r.status == "BLOCK"
            else "can't be judged against its contract."
            if r.status == "UNKNOWN"
            else "matches its contract again."
        ),
        "",
        f"{sym} `{r.address}` · `{r.contract_file}`",
        "",
        *(f"- {x}" for x in r.reasons),
        "",
    ]
    if r.status == "BLOCK":
        lines += [
            "The code and the contract agree; the deployed resource doesn't. It was most likely "
            "changed outside the code (console, CLI, another tool).",
            "",
            "→ restore it from code (re-apply), or update the code and the contract together "
            "with owner approval.",
            "",
        ]
    lines.append("<sub>PosturaNet · read-only check of the deployed resource.</sub>")
    return "\n".join(lines) + "\n"


def deliver_drift(gh: GitHub, r: ContractResult) -> str | None:
    """One issue per drifted resource: a BLOCK opens or updates it, an UNKNOWN only updates
    one that is already open, and a PASS updates and closes it."""
    title = f"PosturaNet: {r.address} drifted from its contract"[:120]
    return gh.upsert_issue(
        drift_marker(r.address),
        title,
        drift_body(r),
        DRIFT_LABELS,
        create=r.status == "BLOCK",
        close=r.status == "PASS",
    )
