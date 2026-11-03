"""The `fix` pipeline: ingest → locate → evidence → contract → fix → validate → deliver.

Modes:
- `dry-run`: no AWS, GitHub or terraform plan, writes nothing. Evidence comes only from
  `--evidence-file`; without it the run ends after locate.
- `check`: everything except opening the PR. Writes the draft contract into the repo.
- `open-pr`: `check`, then opens or updates the PR when every required check passes.

Every outcome, including a stop, becomes a RunRecord. Rendering is left to `output/`.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from posturanet import __version__
from posturanet.aws.session import ClientFactory
from posturanet.configfix import edit_resource, fixes_for
from posturanet.configfix import pr as config_pr
from posturanet.configfix.pr import ConfigProposal
from posturanet.configfix.validate import validate_config_fix
from posturanet.contracts import (
    build_contract,
    contract_path,
    dump_contract,
    load_contract,
    merge_human_fields,
    write_contract,
)
from posturanet.deliver import GitHub, deliver, idempotency_key
from posturanet.deliver.github import PullRequest, push_pr
from posturanet.errors import StageStop
from posturanet.evidence import FlowSource, LogsInsightsSource, collect
from posturanet.evidence.confidence import at_least
from posturanet.evidence.periodicity import describe
from posturanet.ingest import ingest
from posturanet.locate import locate_match
from posturanet.locate.backend import boto3_s3_fetch
from posturanet.models import (
    Confidence,
    Config,
    Finding,
    FixType,
    NetRule,
    Observations,
    ReportStatus,
    RunRecord,
    StageResult,
    StageStatus,
    ValidationReport,
)
from posturanet.proposal import Proposal
from posturanet.synth import make_diff, parse_security_group, synthesize
from posturanet.synth.sg_rules import has_non_cidr_sources, is_internal, rules_from_state
from posturanet.validate import SubprocessTerraform, TerraformRunner, ValidationInputs, validate

Clock = Callable[[], datetime]
Mode = Literal["dry-run", "check", "open-pr"]

STAGES = ("ingest", "locate", "evidence", "contract", "fix", "validate", "deliver")
_MAX_DETAIL_ROWS = 8


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Context:
    mode: Mode = "dry-run"
    clock: Clock = _utcnow
    state_path: Path | None = None
    evidence: FlowSource | None = None
    aws: ClientFactory | None = None
    terraform: TerraformRunner | None = None
    github: GitHub | None = None
    window_days: int | None = None
    stop_after: Literal["contract"] | None = None
    command: str = "fix"
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))


def run_fix(target: str, repo: Path, config: Config, ctx: Context | None = None) -> RunRecord:
    return run_fix_full(target, repo, config, ctx)[0]


def run_fix_full(
    target: str, repo: Path, config: Config, ctx: Context | None = None
) -> tuple[RunRecord, Proposal | None]:
    ctx = ctx or Context()
    record = RunRecord(
        agent_version=__version__,
        command=ctx.command,
        target=target,
        mode=ctx.mode,
        started_at=ctx.clock(),
        result="",
    )
    stage = "ingest"
    try:
        return _run(target, repo, config, ctx, record)
    except StageStop as stop:
        stage = stop.stage or stage
        if stage not in {s.name for s in record.stages}:
            record.stages.append(
                StageResult(
                    name=stage,
                    status=StageStatus.UNKNOWN if stop.unknown else StageStatus.FAIL,
                    summary=stop.reason,
                )
            )
        _skip_rest(record, after=stage, summary="not run")
        record.result = "STOPPED"
        if stop.exit_code == 4:
            record.result_detail = "validation FAIL · no PR opened"
        else:
            record.result_detail = f"{stage} stopped · no PR opened"
        record.why = stop.why or stop.reason
        record.next_steps = stop.next_steps
        record.exit_code = stop.exit_code
        return record, None


def _run(
    target: str, repo: Path, config: Config, ctx: Context, record: RunRecord
) -> tuple[RunRecord, Proposal | None]:
    dry = ctx.mode == "dry-run"

    # --- ingest
    finding = ingest(target)
    record.finding = finding
    if finding.fix_type is FixType.CONFIG_ATTRIBUTE:
        record.stages.append(_ingest_stage(finding))
        return _run_config(finding, repo, config, ctx, record)
    if finding.fix_type is not FixType.SG_INGRESS:
        raise StageStop(
            "ingest",
            f"control {finding.control_id} is not a supported fix type",
            [
                "`posturanet fixes list` shows every control PosturaNet fixes",
                "S3 public access and IAM least privilege arrive in later releases",
            ],
        )
    if finding.control_id == "EC2.2":
        raise StageStop(
            "ingest",
            "EC2.2 (default security group) fixes are not in R1",
            ["remove the default group's rules by hand after moving workloads off it"],
        )
    record.stages.append(_ingest_stage(finding))

    # --- locate
    s3_fetch = boto3_s3_fetch(ctx.aws) if ctx.aws is not None else None
    loc, match = locate_match(finding, repo, config, ctx.state_path, s3_fetch)
    record.location = loc
    owners = ", ".join(loc.owners) if loc.owners else "no owner found"
    record.stages.append(
        StageResult(
            name="locate",
            status=StageStatus.OK,
            summary=f"{loc.file}:{loc.line} → {loc.address} · {owners}",
            details=loc.reasoning,
        )
    )

    # --- evidence
    source = ctx.evidence
    if source is None and not dry:
        source = _logs_insights(config, ctx)
    if source is None:
        _skip_rest(record, after="locate", summary="dry run: pass --evidence-file to go further")
        record.result = "DRY RUN"
        record.result_detail = "ingest and locate complete · no AWS calls, no changes"
        record.unknowns = ["drift: not checked (needs terraform plan)"]
        if not loc.owners:
            record.unknowns.append("owner: no CODEOWNERS rule matches the file")
        record.next_steps = [
            "re-run with --evidence-file <flows.json> to see the proposed fix offline",
            "or drop --dry-run to read flow logs with the read-only role",
        ]
        return record, None

    window = ctx.window_days or config.evidence.window_days
    obs = collect(source, finding.resource.id, loc.address, now=ctx.clock(), window_days=window)
    record.observations = obs
    if obs.confidence is Confidence.NONE:
        raise StageStop(
            "evidence",
            f"no flow logs found for {len(obs.enis)} ENIs on this security group · confidence none"
            if obs.enis
            else "no network interfaces use this security group · confidence none",
            [
                "enable VPC flow logs for the VPC and re-run in 14+ days",
                f"posturanet fix {finding.resource.id}",
            ],
            why="PosturaNet never changes a resource without usage evidence",
            unknown=True,
        )
    minimum = Confidence(config.evidence.min_confidence_for_pr)
    weak = not at_least(obs.confidence, minimum)
    if weak and not dry:
        raise StageStop(
            "evidence",
            f"confidence {obs.confidence.value} ({obs.window.days} days, "
            f"{obs.window.coverage_ratio:.0%} coverage); needs {minimum.value}",
            ["re-run when more flow-log history exists (high needs 60+ days, 95% coverage)"],
            unknown=True,
        )
    record.stages.append(
        StageResult(
            name="evidence",
            status=StageStatus.WARN if weak else StageStatus.OK,
            summary=f"{_source_label(obs.source)} · {obs.window.days} days · "
            f"confidence {obs.confidence.value} · {len(obs.items)} sources",
            details=_evidence_rows(obs),
            expand=True,
        )
    )

    # --- contract
    path = contract_path(repo, config.contracts.dir, loc.address)
    rel_path = path.relative_to(repo).as_posix()
    existing = load_contract(path)
    original_contract = path.read_text(encoding="utf-8") if path.is_file() else None

    sg = parse_security_group(repo / loc.file, loc.line, match.type, match.name)
    current = sg.rules()
    open_rules = [r for r in current if r.is_world]

    if existing is not None and existing.status == "approved":
        if existing.resource != loc.address:
            raise StageStop("contract", f"{rel_path} is for {existing.resource}, not {loc.address}")
        contract, contract_text = existing, None
        contract_summary = f"approved contract · {rel_path}"
    else:
        draft = build_contract(
            obs, open_rules, account=finding.resource.account, region=finding.resource.region
        )
        contract = merge_human_fields(draft, existing)
        contract_text = dump_contract(contract)
        if not dry:
            write_contract(path, contract)
        verb = "built (not written)" if dry else "draft written"
        contract_summary = f"{verb} · {rel_path}"
    review = len(contract.needs_review)
    record.contract_file = rel_path
    record.stages.append(
        StageResult(
            name="contract",
            status=StageStatus.WARN if review else StageStatus.OK,
            summary=contract_summary
            + (
                f" · {review} {'source needs' if review == 1 else 'sources need'} review"
                if review
                else ""
            ),
        )
    )

    if ctx.stop_after == "contract":
        _skip_rest(record, after="contract", summary="not requested")
        record.result = "CONTRACT"
        record.result_detail = (
            f"{len(contract.must_allow)} must_allow · {len(contract.must_deny)} must_deny · "
            f"{review} needs review"
        )
        record.unknowns = [contract.unknown_risk]
        record.next_steps = [f"review {rel_path}, then merge it to approve"]
        return record, None

    # --- fix
    if not open_rules:
        raise StageStop(
            "fix",
            "no ingress block open to 0.0.0.0/0 or ::/0 found in the code",
            ["the open rule may live outside this file or only in AWS (drift); check by hand"],
        )
    if match.ingress is not None and not has_non_cidr_sources(match.ingress):
        if sorted(set(rules_from_state(match.ingress))) != current:
            loc.drift = True
            raise StageStop(
                "fix",
                "drift: ingress in state differs from the code",
                ["run terraform plan and resolve the drift, then re-run"],
            )
        loc.drift = False
    synth = synthesize(contract, current, config.synthesis)
    diff = make_diff(repo, sg, synth, loc.address)
    record.diff = diff
    record.stages.append(StageResult(name="fix", status=StageStatus.OK, summary=diff.summary))

    # --- validate
    tf = ctx.terraform or SubprocessTerraform(config.terraform.binary, config.validation.timeout_s)
    report = validate(
        ValidationInputs(
            repo=repo,
            finding=finding,
            location=loc,
            diff=diff,
            contract=contract,
            synthesis=synth,
            config=config,
            state_path=ctx.state_path,
        ),
        tf,
        offline=dry,
    )
    record.validation = report
    _record_validation(record, report, dry=dry)

    key = idempotency_key(finding.finding_id, contract, diff.sha256)
    proposal = Proposal(
        finding=finding,
        location=loc,
        observations=obs,
        contract=contract,
        contract_file=rel_path,
        contract_text=contract_text,
        synthesis=synth,
        diff=diff,
        report=report,
        idempotency_key=key,
        unknowns=_unknowns(record, synth.out_of_scope),
    )
    record.unknowns = [contract.unknown_risk, *proposal.unknowns]

    # --- deliver
    if ctx.mode != "open-pr":
        why = "dry run" if dry else "not requested (pass --open-pr)"
        record.stages.append(StageResult(name="deliver", status=StageStatus.SKIPPED, summary=why))
        record.result = "DRY RUN" if dry else "VALIDATED"
        record.result_detail = f"risk {proposal.risk} · disruption {proposal.disruption}" + (
            " · no AWS calls, no changes" if dry else ""
        )
        record.next_steps = (
            ["drop --dry-run to run terraform plan with the read-only role"]
            if dry
            else ["re-run with --open-pr to open the pull request"]
        )
        if review:
            record.next_steps.insert(0, f"confirm the owner of {review} needs-review source(s)")
        return record, proposal

    gh = ctx.github or _github(config, ctx)
    local_originals: dict[str, str | None] = {f.path: sg.text for f in diff.files}
    if contract_text is not None:
        local_originals[rel_path] = original_contract
    result = deliver(
        gh,
        proposal,
        base=config.delivery.github.base,
        labels=config.delivery.labels,
        max_open=config.delivery.max_open_prs,
        local_originals=local_originals,
        run_id=f"run_{record.started_at:%Y%m%dT%H%M%SZ}",
    )
    record.pr_url = result.url
    done = {"opened": "PR opened", "updated": "PR updated", "unchanged": "PR already open"}
    record.stages.append(
        StageResult(
            name="deliver",
            status=StageStatus.OK,
            summary=f"{done[result.action]} → {result.url}",
        )
    )
    record.result = "OPENED"
    record.result_detail = f"risk {proposal.risk} · disruption {proposal.disruption}"
    record.next_steps = [
        f"review and merge PR #{result.number}",
        f"after apply, re-run `posturanet fix {finding.resource.id}` to confirm the finding clears",
    ]
    return record, proposal


def _ingest_stage(finding: Finding) -> StageResult:
    return StageResult(
        name="ingest",
        status=StageStatus.OK,
        summary=" · ".join(
            [
                finding.source
                if finding.source == finding.control_id
                else f"{finding.source} {finding.control_id}",
                finding.resource.id,
                finding.severity.value,
            ]
        ),
    )


def _record_validation(record: RunRecord, report: ValidationReport, *, dry: bool) -> None:
    """Append the validate stage; stop the run unless every required check passed."""
    required = [c for c in report.checks if c.required]
    passed = [c for c in required if c.result.value == "pass"]
    notes = [
        f"{c.id} {c.result.value.upper()} ({c.detail})"
        for c in report.checks
        if not c.required and c.result.value != "pass"
    ]
    failing = [
        f"{c.id} {c.result.value.upper()} · {c.detail}"
        for c in required
        if c.result.value != "pass"
    ]
    summary = f"{len(passed)}/{len(required)} required checks PASS" + (
        " · " + " · ".join(notes) if notes else ""
    )
    if report.status is ReportStatus.FAIL:
        record.stages.append(
            StageResult(
                name="validate", status=StageStatus.FAIL, summary=failing[0], details=failing[1:]
            )
        )
        raise _validation_stop(report_failures=failing, exit_code=4)
    if report.status is ReportStatus.INCOMPLETE:
        if not dry:
            record.stages.append(
                StageResult(
                    name="validate",
                    status=StageStatus.FAIL,
                    summary=failing[0],
                    details=failing[1:],
                )
            )
            raise _validation_stop(report_failures=failing, exit_code=3)
        record.stages.append(
            StageResult(
                name="validate",
                status=StageStatus.WARN,
                summary=summary + " · INCOMPLETE (dry run)",
                details=failing,
                expand=True,
            )
        )
    else:
        record.stages.append(StageResult(name="validate", status=StageStatus.OK, summary=summary))


def _run_config(
    finding: Finding, repo: Path, config: Config, ctx: Context, record: RunRecord
) -> tuple[RunRecord, Proposal | None]:
    """Attribute fixes (FR-48): no evidence or contract; the change removes no access."""
    dry = ctx.mode == "dry-run"
    rows = fixes_for(finding.control_id)
    if ctx.stop_after == "contract":
        raise StageStop(
            "contract",
            f"{finding.control_id} is an attribute fix; it has no behavior contract",
            [f"run `posturanet fix {record.target}` instead"],
        )

    # --- locate
    s3_fetch = boto3_s3_fetch(ctx.aws) if ctx.aws is not None else None
    loc, match = locate_match(
        finding,
        repo,
        config,
        ctx.state_path,
        s3_fetch,
        resource_types=list(dict.fromkeys(r.resource_type for r in rows)),
        account_scope=rows[0].scope == "account",
    )
    record.location = loc
    owners = ", ".join(loc.owners) if loc.owners else "no owner found"
    record.stages.append(
        StageResult(
            name="locate",
            status=StageStatus.OK,
            summary=f"{loc.file}:{loc.line} → {loc.address} · {owners}",
            details=loc.reasoning,
        )
    )
    fix = next(r for r in rows if r.resource_type == match.type)
    record.stages.append(
        StageResult(
            name="evidence",
            status=StageStatus.SKIPPED,
            summary="not needed: this setting doesn't remove access or traffic",
        )
    )
    record.stages.append(
        StageResult(
            name="contract",
            status=StageStatus.SKIPPED,
            summary="not needed: attribute fixes have no behavior contract",
        )
    )

    # --- fix
    if "[" in loc.address:
        raise StageStop(
            "fix",
            f"{loc.address} uses count or for_each; the edit would change every instance",
            ["fix this resource by hand for now"],
        )
    diff, edit, original = edit_resource(repo, loc.file, loc.line, loc.address, fix)
    record.diff = diff
    record.stages.append(
        StageResult(
            name="fix",
            status=StageStatus.OK,
            summary=f"{fix.control} · {diff.summary}",
            details=[f"already set: {a}" for a in edit.already],
        )
    )

    # --- validate
    tf = ctx.terraform or SubprocessTerraform(config.terraform.binary, config.validation.timeout_s)
    report = validate_config_fix(
        repo=repo,
        fix=fix,
        address=loc.address,
        file=loc.file,
        line=loc.line,
        diff=diff,
        config=config,
        tf=tf,
        state_path=ctx.state_path,
        offline=dry,
    )
    record.validation = report
    _record_validation(record, report, dry=dry)

    unknowns: list[str] = []
    if not loc.owners:
        unknowns.append("owner: no CODEOWNERS rule matches the file")
    if dry:
        unknowns.append("drift: not checked (needs terraform plan)")
    proposal = ConfigProposal(
        finding=finding,
        location=loc,
        fix=fix,
        diff=diff,
        report=report,
        already=edit.already,
        unknowns=unknowns,
    )
    record.unknowns = [*([fix.note] if fix.note else []), *unknowns]
    detail = f"risk {proposal.risk} · disruption {proposal.disruption}"

    # --- deliver
    if ctx.mode != "open-pr":
        why = "dry run" if dry else "not requested (pass --open-pr)"
        record.stages.append(StageResult(name="deliver", status=StageStatus.SKIPPED, summary=why))
        record.result = "DRY RUN" if dry else "VALIDATED"
        record.result_detail = detail + (" · no AWS calls, no changes" if dry else "")
        record.next_steps = (
            ["drop --dry-run to run terraform plan with the read-only role"]
            if dry
            else ["re-run with --open-pr to open the pull request"]
        )
        return record, None

    gh = ctx.github or _github(config, ctx)
    result = push_pr(
        gh,
        PullRequest(
            finding_id=finding.finding_id,
            key=proposal.idempotency_key,
            branch=config_pr.branch(proposal),
            title=config_pr.title(proposal),
            body=config_pr.body(proposal, run_id=f"run_{record.started_at:%Y%m%dT%H%M%SZ}"),
            labels=config_pr.labels(proposal, config.delivery.labels),
            writes=[
                (
                    fc.path,
                    fc.new_content,
                    f"fix(security): {fix.control} {loc.address} [posturanet]",
                )
                for fc in diff.files
            ],
        ),
        base=config.delivery.github.base,
        max_open=config.delivery.max_open_prs,
        local_originals={loc.file: original},
    )
    record.pr_url = result.url
    done = {"opened": "PR opened", "updated": "PR updated", "unchanged": "PR already open"}
    record.stages.append(
        StageResult(
            name="deliver", status=StageStatus.OK, summary=f"{done[result.action]} → {result.url}"
        )
    )
    record.result = "OPENED"
    record.result_detail = detail
    record.next_steps = [
        f"review and merge PR #{result.number}",
        "after apply, re-run on the finding to confirm the control passes",
    ]
    return record, None


def _validation_stop(*, report_failures: list[str], exit_code: int) -> StageStop:
    first = report_failures[0] if report_failures else "a required check did not pass"
    return StageStop(
        "validate",
        first,
        ["fix the failing check (see above), then re-run"],
        why="every required check must PASS before PosturaNet opens a PR",
        exit_code=exit_code,
    )


def _logs_insights(config: Config, ctx: Context) -> FlowSource:
    group = config.evidence.flow_logs.log_group
    if not group:
        raise StageStop(
            "evidence",
            "evidence.flow_logs.log_group is not set",
            [
                "set evidence.flow_logs.log_group in .posturanet.yml to your VPC flow-log group",
                "or pass --evidence-file with an exported flow-log aggregate",
            ],
        )
    if ctx.aws is None:
        raise StageStop("evidence", "no AWS access configured")
    return LogsInsightsSource(ctx.aws("ec2"), ctx.aws("logs"), group)


def _github(config: Config, ctx: Context) -> GitHub:
    token = ctx.env.get("GITHUB_TOKEN") or ctx.env.get("GH_TOKEN")
    repo = config.delivery.github.repo or ctx.env.get("GITHUB_REPOSITORY")
    if not token:
        raise StageStop(
            "deliver",
            "GITHUB_TOKEN is not set; not authorized to open a PR",
            ["set GITHUB_TOKEN with contents:write and pull-requests:write"],
        )
    if not repo:
        raise StageStop(
            "deliver",
            "target repository unknown",
            ["set delivery.github.repo in .posturanet.yml (owner/name)"],
        )
    return GitHub(token, repo)


def _source_label(source: str) -> str:
    return {"vpc_flow_logs": "vpc flow logs", "flow_logs_file": "flow logs (file)"}.get(
        source, source
    )


def _evidence_rows(obs: Observations) -> list[str]:
    rows = []
    for item in sorted(obs.items, key=lambda i: -i.count)[:_MAX_DETAIL_ROWS]:
        pattern = describe(item.period, item.hours_histogram).replace("@", " at ")
        pattern = pattern.replace(":00Z", ":00 UTC")
        line = f"  {item.cidr:<18} {item.count:>7,} conns · {item.port}/{item.proto} · {pattern}"
        flags = []
        if item.needs_review:
            flags.append("needs review")
        if not is_internal(ipaddress.ip_network(item.cidr)):
            flags.append("external, review owner")
        if flags:
            line += "  ! " + ", ".join(flags)
        rows.append(line)
    extra = len(obs.items) - _MAX_DETAIL_ROWS
    if extra > 0:
        rows.append(f"  … {extra} more (see --format json)")
    return rows


def _unknowns(record: RunRecord, outside: list[NetRule]) -> list[str]:
    out: list[str] = []
    loc = record.location
    if loc is not None and not loc.owners:
        out.append("owner: no CODEOWNERS rule matches the file")
    if loc is not None and loc.drift is None and record.mode == "dry-run":
        out.append("drift: not checked (needs terraform plan)")
    if outside:
        out.append(f"{len(outside)} contract source(s) were never allowed by the open rule")
    return out


def _skip_rest(record: RunRecord, *, after: str, summary: str) -> None:
    for name in STAGES[STAGES.index(after) + 1 :]:
        record.stages.append(StageResult(name=name, status=StageStatus.SKIPPED, summary=summary))
