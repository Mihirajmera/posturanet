"""`posturanet verify <pr>`: did the merged fix apply, clear the finding, and break nothing?

Stages (architecture doc 11, FR-31..FR-34):
- pr: read the PR and the verify spec PosturaNet wrote into its body.
- applied: the Terraform state shows the fix (attributes, or SG ingress rules).
- recheck: the control passes on that state; Security Hub agrees when AWS is reachable.
- watch: SG fixes only; no flow-log REJECTs from contracted sources during the window.
- revert: on a regression, a revert PR (with --open-pr).

Every outcome is a RunRecord with an `Outcome`. CONFIRMED needs every check to pass.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from posturanet import __version__
from posturanet.aws.session import ClientFactory
from posturanet.configfix.catalog import Change
from posturanet.configfix.validate import get_path
from posturanet.deliver.github import GitHub
from posturanet.deliver.idempotency import spec_in
from posturanet.errors import StageStop
from posturanet.evidence.flowlogs import FlowRecord
from posturanet.locate import load_repo_state
from posturanet.locate.backend import boto3_s3_fetch
from posturanet.locate.tfstate import attributes_of
from posturanet.models import (
    Config,
    Outcome,
    OutcomeState,
    RunRecord,
    StageResult,
    StageStatus,
    VerifySpec,
)
from posturanet.synth.sg_rules import Rule, rules_from_state
from posturanet.validate.recheck import recheck, supported
from posturanet.verify.revert import open_revert
from posturanet.verify.signals import (
    LogsInsightsRejects,
    RejectSource,
    finding_status,
    window_end,
)

STAGES = ("pr", "applied", "recheck", "watch", "revert")


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class VerifyContext:
    github: GitHub | None = None
    clock: Callable[[], datetime] = _utcnow
    aws: ClientFactory | None = None
    rejects: RejectSource | None = None
    state_path: Path | None = None
    applied_at: datetime | None = None
    watch_hours: int | None = None
    open_pr: bool = False
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))


def run_verify(
    pr_ref: str, repo: Path, config: Config, ctx: VerifyContext | None = None
) -> RunRecord:
    ctx = ctx or VerifyContext()
    record = RunRecord(
        agent_version=__version__,
        command="verify",
        target=pr_ref,
        mode="open-pr" if ctx.open_pr else "check",
        started_at=ctx.clock(),
        result="",
    )
    try:
        _run(pr_ref, repo, config, ctx, record)
    except StageStop as stop:
        stage = stop.stage if stop.stage in STAGES else "pr"
        if stage not in {s.name for s in record.stages}:
            record.stages.append(
                StageResult(
                    name=stage,
                    status=StageStatus.UNKNOWN if stop.unknown else StageStatus.FAIL,
                    summary=stop.reason,
                )
            )
        _skip_rest(record, stage, "not run")
        record.result = "STOPPED"
        record.result_detail = f"{stage} stopped"
        record.why = stop.why or stop.reason
        record.next_steps = stop.next_steps
        record.exit_code = stop.exit_code
        if record.outcome is not None:
            record.outcome.state = OutcomeState.UNKNOWN
    return record


def parse_pr_ref(pr_ref: str, default_repo: str | None) -> tuple[str, int]:
    """`https://github.com/o/r/pull/12`, `o/r#12` or `12` -> ("o/r", 12)."""
    ref = pr_ref.strip().rstrip("/")
    if "/pull/" in ref:
        left, _, num = ref.partition("/pull/")
        parts = left.split("/")
        repo, number = "/".join(parts[-2:]), num.split("/")[0]
    elif "#" in ref:
        repo, _, number = ref.partition("#")
    else:
        repo, number = default_repo or "", ref
    if not repo or not number.isdigit():
        raise StageStop(
            "pr",
            f"can't read a pull request from {pr_ref!r}",
            ["pass the PR URL, owner/repo#number, or a number with delivery.github.repo set"],
        )
    return repo, int(number)


def _run(pr_ref: str, repo: Path, config: Config, ctx: VerifyContext, record: RunRecord) -> None:
    default_repo = config.delivery.github.repo or ctx.env.get("GITHUB_REPOSITORY")
    slug, number = parse_pr_ref(pr_ref, default_repo)
    gh = ctx.github or _github(slug, ctx)

    # --- pr
    pr = gh.get_pr(number)
    spec = spec_in(pr.get("body"))
    if spec is None:
        raise StageStop(
            "pr",
            f"#{number} has no PosturaNet verify spec",
            ["only fix PRs opened by PosturaNet 0.2 or later can be verified"],
        )
    pr_label = f"{slug}#{number}"
    outcome = Outcome(
        state=OutcomeState.OPENED,
        pr=pr_label,
        finding_id=spec.finding_id,
        control=spec.control,
        address=spec.address,
    )
    record.outcome = outcome
    if not pr.get("merged_at"):
        closed = pr.get("state") == "closed"
        outcome.state = OutcomeState.REJECTED if closed else OutcomeState.OPENED
        record.stages.append(
            StageResult(
                name="pr",
                status=StageStatus.SKIPPED if closed else StageStatus.WARN,
                summary=f"{pr_label} {'closed without merge' if closed else 'not merged yet'}",
            )
        )
        _skip_rest(record, "pr", "not merged")
        record.result = outcome.state.value
        record.result_detail = f"{spec.control} · {spec.address}"
        record.next_steps = [] if closed else ["merge and apply the PR, then re-run verify"]
        return
    outcome.state = OutcomeState.MERGED
    outcome.merged_at = _parse(pr["merged_at"])
    outcome.merge_sha = pr.get("merge_commit_sha")
    record.stages.append(
        StageResult(
            name="pr",
            status=StageStatus.OK,
            summary=f"{pr_label} merged {outcome.merged_at:%Y-%m-%d %H:%M} UTC · {spec.control}",
        )
    )

    # --- applied
    s3_fetch = boto3_s3_fetch(ctx.aws) if ctx.aws is not None else None
    state, label = load_repo_state(repo, config, ctx.state_path, s3_fetch)
    attrs = attributes_of(state, spec.address)
    if attrs is None:
        raise StageStop(
            "applied",
            f"{spec.address} is not in the Terraform state {label}",
            ["check you pointed at the state this PR applies to"],
            unknown=True,
        )
    missing = _not_applied(spec, attrs)
    if missing:
        record.stages.append(
            StageResult(
                name="applied", status=StageStatus.WARN, summary=f"not applied yet: {missing}"
            )
        )
        _skip_rest(record, "applied", "not applied")
        record.result = "NOT APPLIED"
        record.result_detail = f"merged, but {label} doesn't show the fix yet"
        record.next_steps = ["apply the merged change through your pipeline, then re-run verify"]
        record.exit_code = 3
        return
    outcome.state = OutcomeState.APPLIED
    outcome.watch_from = ctx.applied_at or outcome.merged_at
    record.stages.append(
        StageResult(name="applied", status=StageStatus.OK, summary=f"state {label} shows the fix")
    )

    # --- recheck
    ok, detail = _recheck(spec, attrs)
    hub = _hub_note(ctx, spec, outcome.watch_from)
    if ok and hub is not None and hub[0] is False:
        ok, detail = False, hub[1]
    if not ok:
        record.stages.append(StageResult(name="recheck", status=StageStatus.FAIL, summary=detail))
        _skip_rest(record, "recheck", "finding still fails")
        record.result = "STILL FAILING"
        record.result_detail = f"{spec.control} · applied, but the control doesn't pass"
        record.next_steps = [
            "the fix was applied but didn't clear the finding; check for other resources or "
            "rules the control evaluates",
        ]
        record.exit_code = 4
        return
    details = [hub[1]] if hub is not None else ["Security Hub not checked (no AWS access)"]
    record.stages.append(
        StageResult(name="recheck", status=StageStatus.OK, summary=detail, details=details)
    )

    # --- watch
    hours = spec.watch_hours if ctx.watch_hours is None else ctx.watch_hours
    if spec.fix_type != "sg_ingress" or hours == 0:
        why = {
            "s3_public": "not watched: the evidence showed no public use, and denied "
            "anonymous requests can't be told apart from scanners",
        }.get(spec.fix_type, "not needed: attribute fixes remove no access")
        record.stages.append(StageResult(name="watch", status=StageStatus.SKIPPED, summary=why))
        _skip_rest(record, "watch", "no regression")
        _confirm(record, outcome, spec)
        return

    start = outcome.watch_from
    assert start is not None
    until = window_end(start, hours)
    outcome.watch_until = until
    now = ctx.clock()
    source = ctx.rejects or _logs_source(config, ctx)
    if source is None:
        raise StageStop(
            "watch",
            "no flow-log access to watch for blocked traffic",
            [
                "set evidence.flow_logs.log_group and run with AWS access",
                "or pass --rejects-file with exported REJECT records",
            ],
            why="PosturaNet confirms a network fix only after watching for blocked traffic",
            unknown=True,
        )
    rows = source.rejects(spec.resource_id, start, min(now, until))
    regressions = _regressions(rows, spec.must_allow)
    if regressions:
        outcome.state = OutcomeState.REGRESSED
        outcome.regressions = regressions
        record.stages.append(
            StageResult(
                name="watch",
                status=StageStatus.FAIL,
                summary=f"{len(regressions)} contracted source(s) blocked since apply",
                details=regressions,
            )
        )
        _revert(record, outcome, spec, gh, pr, config, ctx)
        return
    if now < until:
        left = until - now
        record.stages.append(
            StageResult(
                name="watch",
                status=StageStatus.WARN,
                summary="no blocked contracted traffic so far · "
                f"{left.total_seconds() / 3600:.0f}h left in the window",
            )
        )
        _skip_rest(record, "watch", "watching")
        record.result = "WATCHING"
        record.result_detail = f"{spec.control} · window ends {until:%Y-%m-%d %H:%M} UTC"
        record.next_steps = [f"re-run verify after {until:%Y-%m-%d %H:%M} UTC to confirm"]
        return
    record.stages.append(
        StageResult(
            name="watch",
            status=StageStatus.OK,
            summary=f"no blocked contracted traffic in {hours}h",
        )
    )
    _skip_rest(record, "watch", "no regression")
    _confirm(record, outcome, spec)


def _confirm(record: RunRecord, outcome: Outcome, spec: VerifySpec) -> None:
    outcome.state = OutcomeState.CONFIRMED
    record.result = "CONFIRMED"
    record.result_detail = f"{spec.control} passes on {spec.address}"
    if spec.fix_type != "sg_ingress":
        record.unknowns = ["confirmed from the Terraform state; live drift after apply isn't seen"]


def _revert(
    record: RunRecord,
    outcome: Outcome,
    spec: VerifySpec,
    gh: GitHub,
    pr: dict[str, object],
    config: Config,
    ctx: VerifyContext,
) -> None:
    record.result = "REGRESSED"
    record.result_detail = f"{spec.control} · contracted traffic is blocked"
    record.exit_code = 4
    if not ctx.open_pr:
        record.stages.append(
            StageResult(
                name="revert", status=StageStatus.SKIPPED, summary="not requested (pass --open-pr)"
            )
        )
        record.next_steps = ["re-run with --open-pr to open the revert PR"]
        return
    result = open_revert(gh, dict(pr), spec, outcome.regressions, base=config.delivery.github.base)
    outcome.revert_pr = result.url
    record.pr_url = result.url
    done = {"opened": "revert PR opened", "updated": "revert PR updated"}
    record.stages.append(
        StageResult(
            name="revert",
            status=StageStatus.OK,
            summary=f"{done.get(result.action, 'revert PR already open')} → {result.url}",
        )
    )
    record.next_steps = [f"review and merge the revert PR #{result.number}"]


def _not_applied(spec: VerifySpec, attrs: dict[str, object]) -> str:
    if spec.fix_type == "sg_ingress":
        live = sorted(set(rules_from_state(_ingress(attrs))))
        want = sorted({Rule(*r) for r in spec.rules})
        return "" if live == want else "ingress in state differs from the fix"
    for raw in spec.changes:
        change = Change.model_validate(raw)
        value = get_path(attrs, change.path)
        if not change.satisfied_by(value):
            return f"{change.path} is {value!r}"
    return ""


def _ingress(attrs: dict[str, object]) -> list[dict[str, object]]:
    ingress = attrs.get("ingress")
    return [r for r in ingress if isinstance(r, dict)] if isinstance(ingress, list) else []


def _recheck(spec: VerifySpec, attrs: dict[str, object]) -> tuple[bool, str]:
    if spec.fix_type == "sg_ingress":
        if not supported(spec.control):
            return False, f"no re-check for {spec.control}"
        ok, detail = recheck(spec.control, rules_from_state(_ingress(attrs)))
        return ok, detail.replace("planned config", "applied state")
    return True, f"{spec.control} passes on the applied state"


def _hub_note(
    ctx: VerifyContext, spec: VerifySpec, applied: datetime | None
) -> tuple[bool | None, str] | None:
    """(passes?, detail) from Security Hub; passes is None while it hasn't re-evaluated."""
    if ctx.aws is None:
        return None
    found = finding_status(ctx.aws("securityhub"), spec.finding_id)
    if found is None:
        return None, "Security Hub: finding no longer listed"
    status, updated = found
    if status in ("PASSED", "ARCHIVED"):
        return True, f"Security Hub: {status}"
    if applied is not None and (updated is None or updated <= applied):
        return None, "Security Hub: not re-evaluated since apply yet"
    return False, f"Security Hub still reports {status} after apply"


def _regressions(rows: list[FlowRecord], must_allow: list[tuple[str, int, str]]) -> list[str]:
    hits: dict[tuple[str, int, str], int] = {}
    for row in rows:
        src = ipaddress.ip_network(row.src)
        for cidr, port, proto in must_allow:
            net = ipaddress.ip_network(cidr, strict=False)
            if src.version != net.version or not src.subnet_of(net):  # type: ignore[arg-type]
                continue
            if proto not in ("-1", row.proto) or (proto != "-1" and port != row.port):
                continue
            key = (row.src, row.port, row.proto)
            hits[key] = hits.get(key, 0) + row.count
    return [
        f"{src} → {port}/{proto} · {n:,} blocked (allowed by the contract)"
        for (src, port, proto), n in sorted(hits.items())
    ]


def _logs_source(config: Config, ctx: VerifyContext) -> RejectSource | None:
    group = config.evidence.flow_logs.log_group
    if ctx.aws is None or not group:
        return None
    return LogsInsightsRejects(ctx.aws("ec2"), ctx.aws("logs"), group)


def _github(slug: str, ctx: VerifyContext) -> GitHub:
    token = ctx.env.get("GITHUB_TOKEN") or ctx.env.get("GH_TOKEN")
    if not token:
        raise StageStop(
            "pr",
            "GITHUB_TOKEN is not set; can't read the pull request",
            ["set GITHUB_TOKEN (pull-requests:read; contents:write to open a revert PR)"],
        )
    return GitHub(token, slug)


def _parse(value: object) -> datetime:
    text = str(value).replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _skip_rest(record: RunRecord, after: str, summary: str) -> None:
    for name in STAGES[STAGES.index(after) + 1 :]:
        record.stages.append(StageResult(name=name, status=StageStatus.SKIPPED, summary=summary))


__all__ = ["VerifyContext", "parse_pr_ref", "run_verify"]
