"""`posturanet` CLI. The only place that maps errors to exit codes (architecture doc 12)."""

from __future__ import annotations

import json
import os
import re
import sys
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, TextIO

import typer

from posturanet import __version__
from posturanet.aws.readonly import iam_policy
from posturanet.errors import PosturaNetError, UsageError
from posturanet.evidence import FileSource
from posturanet.models import RunRecord
from posturanet.models.config import load_config
from posturanet.output import banner, console
from posturanet.pipeline import Context, Mode, run_fix

if TYPE_CHECKING:
    from posturanet.gate import GateResult

app = typer.Typer(
    name="posturanet",
    help="PosturaNet: evidence-backed Terraform fixes for cloud security findings.",
    add_completion=False,
)
contract_app = typer.Typer(help="Build and check behavior contracts.", no_args_is_help=True)
app.add_typer(contract_app, name="contract")
hook_app = typer.Typer(help="Editor and AI agent hooks.", no_args_is_help=True)
app.add_typer(hook_app, name="hook")
fixes_app = typer.Typer(help="List the controls PosturaNet fixes.", no_args_is_help=True)
app.add_typer(fixes_app, name="fixes")


class OutputFormat(StrEnum):
    TEXT = "text"
    JSON = "json"


RepoOpt = Annotated[Path, typer.Option(help="Terraform repo root.")]
StateOpt = Annotated[
    Path | None, typer.Option(help="Local copy of the Terraform state (never commit it).")
]
EvidenceOpt = Annotated[
    Path | None,
    typer.Option("--evidence-file", help="Exported flow-log aggregate (JSON) instead of AWS."),
]
WindowOpt = Annotated[str | None, typer.Option(help="Evidence window, e.g. 90d.")]
FormatOpt = Annotated[OutputFormat, typer.Option("--format")]
AsciiOpt = Annotated[bool, typer.Option("--ascii", help="ASCII-only output.")]


def _version(value: bool) -> None:
    if value:
        typer.echo(f"PosturaNet {__version__}")
        raise typer.Exit(0)


def _banner(stream: TextIO) -> None:
    if banner.allowed(stream):
        console.write(banner.render(ascii_mode=console.wants_ascii(stream)), stream)


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    if ctx.invoked_subcommand is None:
        _banner(sys.stdout)
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


def _window(value: str | None) -> int | None:
    if value is None:
        return None
    m = re.fullmatch(r"(\d+)d?", value.strip())
    if not m or not 1 <= int(m.group(1)) <= 400:
        raise UsageError(f"--window must look like 90d (1-400 days), got {value!r}")
    return int(m.group(1))


def _context(
    mode: Mode,
    repo: Path,
    state: Path | None,
    evidence_file: Path | None,
    window: str | None,
) -> Context:
    if not repo.is_dir():
        raise UsageError(f"--repo is not a directory: {repo}")
    if evidence_file is not None and not evidence_file.is_file():
        raise UsageError(f"--evidence-file not found: {evidence_file}")
    ctx = Context(
        mode=mode,
        state_path=state,
        evidence=FileSource(evidence_file) if evidence_file else None,
        window_days=_window(window),
    )
    if mode != "dry-run":
        from posturanet.aws.session import boto3_factory

        config, _ = load_config(repo)
        ctx.aws = boto3_factory(config.aws)
    return ctx


def _emit(record: RunRecord, output_format: OutputFormat, ascii_mode: bool) -> None:
    if output_format is OutputFormat.JSON:
        console.write(console.render_json(record))
    else:
        use_ascii = ascii_mode or console.wants_ascii(sys.stdout)
        console.write(console.render_text(record, ascii_mode=use_ascii))
    raise typer.Exit(record.exit_code)


def _fail(exc: PosturaNetError) -> typer.Exit:
    typer.echo(f"error: {exc}", err=True)
    return typer.Exit(exc.exit_code)


@app.command()
def fix(
    target: Annotated[str, typer.Argument(help="ASFF finding file (.json) or a resource id.")],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="No AWS, GitHub or terraform plan; writes nothing.")
    ] = False,
    open_pr: Annotated[
        bool, typer.Option("--open-pr", help="Open or update the PR when every check passes.")
    ] = False,
    repo: RepoOpt = Path("."),
    state: StateOpt = None,
    evidence_file: EvidenceOpt = None,
    window: WindowOpt = None,
    output_format: FormatOpt = OutputFormat.TEXT,
    ascii_mode: AsciiOpt = False,
) -> None:
    """Turn a finding into a validated fix, and optionally a PR."""
    try:
        if dry_run and open_pr:
            raise UsageError("--dry-run and --open-pr can't be used together")
        mode: Mode = "dry-run" if dry_run else ("open-pr" if open_pr else "check")
        ctx = _context(mode, repo, state, evidence_file, window)
        config, _ = load_config(repo)
        record = run_fix(target, repo, config, ctx)
    except PosturaNetError as exc:
        raise _fail(exc) from exc
    _emit(record, output_format, ascii_mode)


@contract_app.command("build")
def contract_build(
    target: Annotated[str, typer.Argument(help="ASFF finding file or security group id.")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Don't write the contract.")] = False,
    repo: RepoOpt = Path("."),
    state: StateOpt = None,
    evidence_file: EvidenceOpt = None,
    window: WindowOpt = None,
    output_format: FormatOpt = OutputFormat.TEXT,
    ascii_mode: AsciiOpt = False,
) -> None:
    """Build a draft behavior contract from observed usage."""
    try:
        ctx = _context("dry-run" if dry_run else "check", repo, state, evidence_file, window)
        ctx.stop_after = "contract"
        ctx.command = "contract build"
        config, _ = load_config(repo)
        record = run_fix(target, repo, config, ctx)
    except PosturaNetError as exc:
        raise _fail(exc) from exc
    _emit(record, output_format, ascii_mode)


_GATE_EXIT = {"PASS": 0, "BLOCK": 5, "UNKNOWN": 3}


def _publish_check(result: GateResult, sha: str | None) -> str:
    from posturanet.deliver.checks import publish
    from posturanet.deliver.github import GitHub

    token = os.environ.get("GITHUB_TOKEN")
    repo_slug = os.environ.get("GITHUB_REPOSITORY")
    head = sha or os.environ.get("GITHUB_SHA")
    if not token or not repo_slug or not head:
        raise UsageError(
            "--github-check needs GITHUB_TOKEN, GITHUB_REPOSITORY and --sha (or GITHUB_SHA)"
        )
    return publish(GitHub(token, repo_slug), result, head)


@contract_app.command("check")
def contract_check(
    plan: Annotated[
        Path | None, typer.Option("--plan", help="`terraform show -json` output.")
    ] = None,
    source: Annotated[
        bool,
        typer.Option("--source", help="Check the Terraform source instead of a plan (offline)."),
    ] = False,
    files: Annotated[
        list[Path] | None,
        typer.Option("--file", help="With --source: only groups defined in this .tf file."),
    ] = None,
    github_check: Annotated[
        bool, typer.Option("--github-check", help="Publish the result as a GitHub check run.")
    ] = False,
    sha: Annotated[str | None, typer.Option(help="Commit for the check run.")] = None,
    repo: RepoOpt = Path("."),
    output_format: FormatOpt = OutputFormat.TEXT,
    ascii_mode: AsciiOpt = False,
) -> None:
    """Check a change against the contracts in the repo. Exit 5 on BLOCK, 3 on UNKNOWN."""
    from posturanet.gate import check_plan, check_source

    try:
        if (plan is None) == (not source):
            raise UsageError("use exactly one of --plan or --source")
        if files and not source:
            raise UsageError("--file only works with --source")
        config, _ = load_config(repo)
        if plan is not None:
            if not plan.is_file():
                raise UsageError(f"--plan not found: {plan}")
            try:
                plan_doc = json.loads(plan.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise UsageError(f"--plan is not JSON (use `terraform show -json`): {exc}") from exc
            result = check_plan(plan_doc, repo, config)
        else:
            result = check_source(repo, config, files or None)
        check_url = _publish_check(result, sha) if github_check else None
    except PosturaNetError as exc:
        raise _fail(exc) from exc

    if output_format is OutputFormat.JSON:
        doc = result.to_dict()
        if check_url is not None:
            doc["check_url"] = check_url
        console.write(json.dumps(doc, indent=2) + "\n")
    else:
        console.write(console.render_gate(result, ascii_mode or console.wants_ascii(sys.stdout)))
    raise typer.Exit(_GATE_EXIT[result.status])


@hook_app.command("claude-code")
def hook_claude_code(repo: RepoOpt = Path(".")) -> None:
    """Claude Code PostToolUse hook: check an edited .tf file against the contracts.

    Reads the hook event from stdin. On BLOCK, tells Claude why so it can fix its own change.
    Never fails the session on its own errors.
    """
    from posturanet.hooks import claude_code

    console.write(claude_code(sys.stdin.read(), repo))
    raise typer.Exit(0)


def _fix_rows() -> list[dict[str, str]]:
    from posturanet.configfix import catalog
    from posturanet.ingest.controls import _control_map

    rows = [
        {
            "control": control,
            "kind": "evidence",
            "resource_type": "aws_security_group",
            "change": "replace open ingress with the sources seen in flow logs",
        }
        for control, ftype in _control_map().items()
        if ftype.value == "sg_ingress" and control != "EC2.2"
    ]
    rows += [
        {
            "control": f.control,
            "kind": "config",
            "resource_type": f.resource_type,
            "change": f.change_summary,
        }
        for f in catalog()
    ]
    return rows


@fixes_app.command("list")
def fixes_list(
    service: Annotated[
        str | None, typer.Option(help="Only this service, e.g. rds or dynamodb.")
    ] = None,
    output_format: FormatOpt = OutputFormat.TEXT,
) -> None:
    """Every control PosturaNet can turn into a PR, and what it changes."""
    rows = _fix_rows()
    if service:
        rows = [r for r in rows if r["control"].split(".")[0].lower() == service.lower()]
    if output_format is OutputFormat.JSON:
        console.write(json.dumps(rows, indent=2) + "\n")
        raise typer.Exit(0)
    controls = {r["control"] for r in rows}
    dot = "-" if console.wants_ascii(sys.stdout) else "·"
    lines = [f"{len(controls)} controls {dot} {len(rows)} fixes", ""]
    for r in rows:
        lines.append(f"  {r['control']:<18} {r['kind']:<9} {r['resource_type']:<40} {r['change']}")
    lines += ["", "Details: posturanet fixes show <control>"]
    console.write("\n".join(lines) + "\n")


@fixes_app.command("show")
def fixes_show(
    control: Annotated[str, typer.Argument(help="Security Hub control id, e.g. RDS.8.")],
    output_format: FormatOpt = OutputFormat.TEXT,
) -> None:
    """What PosturaNet changes for one control, and why it's safe to review."""
    from posturanet.configfix import fixes_for

    found = fixes_for(control)
    if not found:
        sg = [r for r in _fix_rows() if r["control"] == control]
        if sg:
            dot = "-" if console.wants_ascii(sys.stdout) else "·"
            console.write(
                f"{control} {dot} evidence fix on aws_security_group\n"
                "  Replaces open ingress with the sources seen in VPC flow logs.\n"
                "  Needs flow-log evidence and a behavior contract.\n"
            )
            raise typer.Exit(0)
        typer.echo(f"error: PosturaNet has no fix for {control} yet", err=True)
        raise typer.Exit(2)
    if output_format is OutputFormat.JSON:
        console.write(json.dumps([f.model_dump(by_alias=True) for f in found], indent=2) + "\n")
        raise typer.Exit(0)
    dot = "-" if console.wants_ascii(sys.stdout) else "·"
    lines: list[str] = []
    for f in found:
        lines += [f"{f.control} {dot} {f.title}", f"  resource  {f.resource_type}"]
        if f.scope == "account":
            lines.append("  scope     account (the one resource of this type in state)")
        lines += [f"  change    {c.describe()}" for c in f.changes]
        lines += [
            f"  when      {c.path} is " + ", ".join("absent" if v is None else v for v in c.in_)
            for c in f.when
        ]
        lines += [f"  why       {f.why}", f"  risk      {f.risk}"]
        if f.note:
            lines.append(f"  note      {f.note}")
        lines.append("")
    console.write("\n".join(lines))


@app.command()
def verify(
    pr: Annotated[str, typer.Argument(help="Fix PR: URL, owner/repo#123, or a number.")],
    open_pr: Annotated[
        bool, typer.Option("--open-pr", help="Open a revert PR if the fix regressed.")
    ] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="No AWS calls; needs --state and --rejects-file.")
    ] = False,
    repo: RepoOpt = Path("."),
    state: StateOpt = None,
    rejects_file: Annotated[
        Path | None,
        typer.Option("--rejects-file", help="Exported flow-log REJECT records (JSON)."),
    ] = None,
    applied_at: Annotated[
        str | None, typer.Option(help="When the fix was applied (ISO 8601); default: merge time.")
    ] = None,
    window: Annotated[
        str | None, typer.Option(help="Watch window, e.g. 72h. Default: the PR's own.")
    ] = None,
    output_format: FormatOpt = OutputFormat.TEXT,
    ascii_mode: AsciiOpt = False,
) -> None:
    """After merge: check the fix applied, the finding passes and nothing it kept got blocked."""
    from datetime import UTC, datetime

    from posturanet.verify import VerifyContext, run_verify
    from posturanet.verify.signals import RejectFile

    try:
        if not repo.is_dir():
            raise UsageError(f"--repo is not a directory: {repo}")
        if rejects_file is not None and not rejects_file.is_file():
            raise UsageError(f"--rejects-file not found: {rejects_file}")
        hours = None
        if window is not None:
            m = re.fullmatch(r"(\d+)h?", window.strip())
            if not m or not 0 <= int(m.group(1)) <= 24 * 30:
                raise UsageError(f"--window must look like 72h (0-720 hours), got {window!r}")
            hours = int(m.group(1))
        applied = None
        if applied_at is not None:
            try:
                applied = datetime.fromisoformat(applied_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise UsageError(f"--applied-at is not ISO 8601: {applied_at!r}") from exc
            if applied.tzinfo is None:
                applied = applied.replace(tzinfo=UTC)
        config, _ = load_config(repo)
        ctx = VerifyContext(
            state_path=state,
            rejects=RejectFile(rejects_file) if rejects_file else None,
            applied_at=applied,
            watch_hours=hours,
            open_pr=open_pr,
        )
        if not offline:
            from posturanet.aws.session import boto3_factory

            ctx.aws = boto3_factory(config.aws)
        record = run_verify(pr, repo, config, ctx)
    except PosturaNetError as exc:
        raise _fail(exc) from exc
    _emit(record, output_format, ascii_mode)


@app.command()
def init() -> None:
    """Print the read-only IAM policy for PosturaNet's role. Writes nothing."""
    _banner(sys.stderr)  # stderr, so `posturanet init > policy.json` stays clean JSON
    console.write(json.dumps(iam_policy(), indent=2) + "\n")


@app.command()
def mcp() -> None:
    """Run the read-only MCP server over stdio."""
    try:
        from posturanet.mcp.server import serve
    except ImportError as exc:
        typer.echo("error: install the MCP extra: pip install 'posturanet[mcp]'", err=True)
        raise typer.Exit(2) from exc
    serve()


def main() -> None:
    app()
