"""`posturanet` CLI. The only place that maps errors to exit codes (architecture doc 12)."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, TextIO

import typer

from posturanet import __version__
from posturanet.aws.readonly import iam_policy
from posturanet.errors import PosturaNetError, StageStop, UsageError
from posturanet.evidence import FileSource
from posturanet.models import RunRecord
from posturanet.models.config import load_config
from posturanet.models.iam import IamApproval
from posturanet.outcomes import EXCEPTIONS_FILE, load_exceptions, outcome, runbook_for
from posturanet.output import banner, console
from posturanet.output.frame import Frame
from posturanet.output.style import Style, wants_color
from posturanet.output.symbols import to_ascii
from posturanet.pipeline import Context, Mode, run_fix

if TYPE_CHECKING:
    from posturanet.gate import GateResult
    from posturanet.ingest import Entry

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
findings_app = typer.Typer(
    help="Read finding files from Security Hub (findings and remediation plans), Prowler, "
    "Checkov or Trivy.",
    no_args_is_help=True,
)
app.add_typer(findings_app, name="findings")


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
ExceptionsOpt = Annotated[
    Path,
    typer.Option("--exceptions", help="Accepted risks: control, resource, owner, reason, expires."),
]


def _examples(*pairs: tuple[str, str]) -> str:
    """`--help` epilog: commands that are safe to copy, each with what it does."""
    lines = [line for cmd, what in pairs for line in (f"# {what}", f"$ {cmd}")]
    return "Examples:\n\n\b\n" + "\n".join(lines)  # \b: Click keeps these lines as written


def _version(value: bool) -> None:
    if value:
        typer.echo(f"PosturaNet {__version__}")
        raise typer.Exit(0)


def _banner(stream: TextIO) -> None:
    if banner.allowed(stream):
        console.write(banner.render(ascii_mode=console.wants_ascii(stream), width=_cols()), stream)


def _cols() -> int | None:
    """Terminal columns for a person at a terminal; None (no limit) for pipes and tests."""
    isatty = getattr(sys.stdout, "isatty", None)
    return shutil.get_terminal_size().columns if isatty and isatty() else None


def _frame(ascii_mode: bool = False) -> Frame:
    use_ascii = ascii_mode or console.wants_ascii(sys.stdout)
    return Frame(use_ascii, Style(wants_color(sys.stdout)), _cols())


def _framed(frame: Frame, lines: list[str]) -> None:
    text = "\n".join(lines) + "\n"
    console.write(to_ascii(text) if frame.ascii_mode else text)


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
        f = _frame(ascii_mode)
        text = console.render_text(record, ascii_mode=f.ascii_mode, style=f.style, width=f.width)
        console.write(text)
    raise typer.Exit(record.exit_code)


def _fail(exc: PosturaNetError) -> typer.Exit:
    typer.echo(f"error: {exc}", err=True)
    return typer.Exit(exc.exit_code)


@app.command(epilog=_examples(
    ("posturanet fix findings/EC2.13-sg-0a91f3c2.json --dry-run --repo infra/", "see the fix; no AWS, writes nothing"),  # noqa: E501 (copyable example)
    ("posturanet fix finding.json --dry-run --repo infra/ --evidence-file flows.json", "the full fix offline, from exported flow logs"),  # noqa: E501 (copyable example)
    ("posturanet fix finding.json --repo infra/", "read evidence with the read-only role and run terraform plan"),  # noqa: E501 (copyable example)
    ("posturanet fix finding.json --repo infra/ --open-pr", "open the PR when every check passes"),
    ("posturanet fix sg-0a91f3c2 --dry-run --repo infra/", "a security group id instead of a finding file"),  # noqa: E501 (copyable example)
))  # fmt: skip
def fix(
    target: Annotated[
        str, typer.Argument(help="Finding file (ASFF, OCSF, Checkov, Trivy) or a resource id.")
    ],
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
        if record.approvals and output_format is OutputFormat.TEXT and _interactive():
            _show(record, ascii_mode)
            approval = _ask_approval(record, ctx.clock().date().isoformat())
            if approval is None:
                typer.echo("Not approved. Nothing was changed.")
                raise typer.Exit(record.exit_code)
            # Preview first: the before and after, with no contract written and no PR.
            ctx.approval, ctx.preview = approval, True
            preview = run_fix(target, repo, config, ctx)
            if preview.result == "STOPPED":
                _emit(preview, output_format, ascii_mode)
            _show(preview, ascii_mode)
            question = "Approve this change" + (" and open the PR?" if open_pr else "?")
            if not typer.confirm(question, default=False):
                typer.echo("Not approved. Nothing was changed.")
                raise typer.Exit(3)
            ctx.preview = False
            record = run_fix(target, repo, config, ctx)
    except PosturaNetError as exc:
        raise _fail(exc) from exc
    _emit(record, output_format, ascii_mode)


def _interactive() -> bool:
    """A person at a terminal: never in CI, pipes or JSON output."""
    if any(os.environ.get(v) for v in banner._CI_VARS):
        return False
    return sys.stdin.isatty() and sys.stdout.isatty()


def _show(record: RunRecord, ascii_mode: bool) -> None:
    f = _frame(ascii_mode)
    console.write(
        console.render_text(record, ascii_mode=f.ascii_mode, style=f.style, width=f.width)
    )


def _ask_approval(record: RunRecord, today: str) -> IamApproval | None:
    """Ask about each stop a person can clear. None: they declined one."""
    import getpass

    reviewed: list[str] = []
    keep: list[str] = []
    typer.echo("\nYou can approve these here. Your answers go into the contract and the PR.\n")
    for item in record.approvals:
        if item.kind == "untracked":
            ns = item.name.split(":", 1)[0]
            typer.echo(f"{item.name}: IAM doesn't record whether it's used.")
            if typer.confirm(f"Keep {item.name}?", default=True):
                keep.append(item.name)
            elif typer.confirm(
                f"Remove {item.name}? Anything that passes roles breaks", default=False
            ):
                reviewed.append(ns)
            else:
                return None
            continue
        seen = ", ".join(item.used) or "none"
        typer.echo(f"{item.name}: actions seen in use: {seen}")
        typer.echo(
            f"  IAM doesn't record {item.name} data actions (object or item reads and writes). "
            f"After the fix, any {item.name} action not kept is denied."
        )
        while True:
            more = typer.prompt(
                f"  Other {item.name} actions to keep, comma-separated (Enter for none)",
                default="",
                show_default=False,
            )
            extra = [a.strip() for a in more.split(",") if a.strip()]
            bad = [a for a in extra if not _ACTION.match(a) or a.split(":")[0].lower() != item.name]
            if not bad:
                break
            typer.echo(
                f"  not {item.name} actions: {', '.join(bad)} (for example {item.name}:GetObject)"
            )
        if not typer.confirm(f"Approve the {item.name} action list?", default=False):
            return None
        reviewed.append(item.name)
        keep += extra
    return IamApproval(reviewed_services=reviewed, keep=keep, by=getpass.getuser(), at=today)


_ACTION = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9]+$")


@contract_app.command("build", epilog=_examples(
    ("posturanet contract build sg-0a91f3c2 --repo infra/", "draft the contract from flow logs"),
    ("posturanet contract build sg-0a91f3c2 --repo infra/ --dry-run", "show it; write nothing"),
))  # fmt: skip
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


@contract_app.command("check", epilog=_examples(
    ("posturanet contract check --source --repo infra/", "offline, from the edited .tf files"),
    ("posturanet contract check --source --file infra/sg.tf", "only groups in one file"),
    ("terraform show -json plan.out > plan.json && posturanet contract check --plan plan.json", "in CI, from a plan"),  # noqa: E501 (copyable example)
))  # fmt: skip
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
        f = _frame(ascii_mode)
        console.write(console.render_gate(result, f.ascii_mode, f.style, width=f.width))
    raise typer.Exit(_GATE_EXIT[result.status])


@hook_app.command("claude-code", epilog=_examples(
    ("/plugin install posturanet@posturanet", "in Claude Code: installs this hook for you"),
))  # fmt: skip
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


@fixes_app.command("list", epilog=_examples(
    ("posturanet fixes list", "every control PosturaNet fixes"),
    ("posturanet fixes list --service rds", "one service"),
    ("posturanet fixes list --format json", "for scripts"),
))  # fmt: skip
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
    f = _frame()
    lines = f.open(console.header("fixes list", service or "", f.style))
    lines += [f.step(f"{len(controls)} controls · {len(rows)} fixes", info=True), f.bar()]
    table = [f.style("bold", f"{'control':<18} {'kind':<9} {'resource':<40} change")]
    table += [
        f"{r['control']:<18} {r['kind']:<9} {r['resource_type']:<40} {r['change']}" for r in rows
    ]
    lines += f.box("Fixes", table)
    lines += f.close("Details: posturanet fixes show <control>")
    _framed(f, lines)


@fixes_app.command("show", epilog=_examples(
    ("posturanet fixes show RDS.8", "what the fix changes, when, and its risk"),
    ("posturanet fixes show EC2.19", "an evidence fix (security groups)"),
))  # fmt: skip
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
            fr = _frame()
            rows = [
                "resource  aws_security_group",
                "change    replaces open ingress with the sources seen in VPC flow logs",
                "needs     flow-log evidence and a behavior contract",
            ]
            lines = fr.open(console.header("fixes show", control, fr.style))
            lines += fr.box(f"{control} · evidence fix", rows)
            lines += fr.close("Fix one: posturanet fix <finding.json> --dry-run")
            _framed(fr, lines)
            raise typer.Exit(0)
        steps = runbook_for(control)
        if steps:
            fr = _frame()
            lines = fr.open(console.header("fixes show", control, fr.style))
            lines += [fr.step("Not a Terraform change: a person does these steps", info=True)]
            lines += [fr.bar()]
            lines += fr.box(f"{control} · runbook", [f"{i}. {t}" for i, t in enumerate(steps, 1)])
            lines += fr.close("Then re-run your scanner; the finding should pass.")
            _framed(fr, lines)
            raise typer.Exit(0)
        typer.echo(f"error: PosturaNet has no fix for {control} yet", err=True)
        raise typer.Exit(2)
    if output_format is OutputFormat.JSON:
        console.write(json.dumps([f.model_dump(by_alias=True) for f in found], indent=2) + "\n")
        raise typer.Exit(0)
    fr = _frame()
    lines = fr.open(console.header("fixes show", control, fr.style))
    for f in found:
        rows = [f"resource  {f.resource_type}"]
        if f.scope == "account":
            rows.append("scope     account (the one resource of this type in state)")
        rows += [f"change    {c.describe()}" for c in f.changes]
        rows += [
            f"when      {c.path} is " + ", ".join("absent" if v is None else v for v in c.in_)
            for c in f.when
        ]
        risk = fr.style("warning", f.risk) if f.risk == "medium" else f.risk
        rows += [f"why       {f.why}", f"risk      {risk}"]
        if f.note:
            rows.append(f"note      {f.note}")
        lines += fr.box(f"{f.control} · {f.title}", rows)
    lines += fr.close("Fix one: posturanet fix <finding.json> --dry-run")
    _framed(fr, lines)


FindingsFileArg = Annotated[
    Path,
    typer.Argument(help="Finding file: Security Hub ASFF, OCSF (Prowler), Checkov or Trivy JSON."),
]


@findings_app.command("list", epilog=_examples(
    ("posturanet findings list scan.json", "the findings PosturaNet can fix"),
    ("posturanet findings list scan.json --all", "every finding, and why the rest can't be fixed yet"),  # noqa: E501 (copyable example)
    ("posturanet findings list plans.json --all", "Security Hub remediation plans"),
))  # fmt: skip
def findings_list(
    path: FindingsFileArg,
    show_all: Annotated[
        bool, typer.Option("--all", help="Also show findings PosturaNet can't fix, and why.")
    ] = False,
    output_format: FormatOpt = OutputFormat.TEXT,
    exceptions: ExceptionsOpt = EXCEPTIONS_FILE,
) -> None:
    """The findings in a file, and how each one ends: a fix, a runbook or an accepted risk."""
    from posturanet.ingest import read_findings

    try:
        found = read_findings(path)
        accepted = load_exceptions(exceptions)
    except PosturaNetError as exc:
        raise _fail(exc) from exc
    today = datetime.now(UTC).date()
    outcomes = {e.index: outcome(e, accepted, today) for e in found.entries}
    shown = found.entries if show_all else found.fixable
    rows = [_finding_row(e, outcomes[e.index]) for e in shown]
    if output_format is OutputFormat.JSON:
        console.write(json.dumps(rows, indent=2) + "\n")
        raise typer.Exit(0)
    f = _frame()
    lines = f.open(console.header("findings list", path.name, f.style))
    counts = Counter(kind for kind, _ in outcomes.values())
    total = len(found.entries) - counts["passed"]  # coverage counts failed findings only
    covered = total - counts["none"]
    summary = (
        f"{found.format.upper()} · {total} failed · {counts['fix']} fix · "
        f"{counts['runbook']} runbook · {counts['exception']} accepted · "
        f"coverage {covered}/{total}" + (f" ({100 * covered // total}%)" if total else "")
    )
    lines += [f.step(summary, info=True, token="success" if covered else "muted"), f.bar()]
    if rows:
        head = f"{'#':>4}  {'outcome':<10} {'control':<14} {'fix':<20} {'severity':<9} resource"
        table = [f.style("bold", head)]
        for r in rows:
            resource = r["resource"] or "-"
            line = (
                f"{r['index']:>4}  {r['outcome']:<10} {r['control']:<14} {r['fix']:<20} "
                f"{r['severity']:<9} {resource}"
            )
            if r["reason"]:
                line += f.style("muted", f"  ({r['reason']})")
            table.append(line)
        lines += f.box("Findings", table)
    if found.fixable:
        lines += f.close(f"Next: posturanet findings split {path} --out findings/")
    elif show_all:
        lines += f.close("Nothing PosturaNet can fix in this file yet.")
    else:
        lines += f.close("Nothing to fix here. See every finding with --all.")
    _framed(f, lines)


@findings_app.command("split", epilog=_examples(
    ("posturanet findings split scan.json --out findings/", "one file per fixable finding"),
))  # fmt: skip
def findings_split(
    path: FindingsFileArg,
    out: Annotated[Path, typer.Option("--out", help="Folder for one file per finding.")] = Path(
        "findings"
    ),
    exceptions: ExceptionsOpt = EXCEPTIONS_FILE,
) -> None:
    """Write each finding PosturaNet can fix to its own file, ready for `posturanet fix`."""
    from posturanet.ingest import document_for, read_findings

    try:
        found = read_findings(path)
        accepted = load_exceptions(exceptions)
    except PosturaNetError as exc:
        raise _fail(exc) from exc
    today = datetime.now(UTC).date()
    to_fix = [e for e in found.fixable if outcome(e, accepted, today)[0] == "fix"]
    skipped = len(found.fixable) - len(to_fix)
    if not to_fix:
        typer.echo(f"{path.name}: no failed findings PosturaNet can fix; nothing written")
        raise typer.Exit(0)
    out.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    written: list[Path] = []
    for e in to_fix:
        if e.finding is None:
            continue
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{e.finding.control_id}-{e.finding.resource.id}")
        name, n = stem, 2
        while name in used:
            name, n = f"{stem}-{n}", n + 1
        used.add(name)
        doc = document_for(e.item, found.format)
        target = out / f"{name}.json"
        target.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
        written.append(target)
    f = _frame()
    lines = f.open(console.header("findings split", path.name, f.style))
    lines += [f.step(f"Read {len(found.fixable)} findings PosturaNet can fix"), f.bar()]
    if skipped:
        lines += [f.step(f"Skipped {skipped} accepted in {exceptions.as_posix()}", info=True)]
        lines += [f.bar()]
    lines += f.box(
        f"Wrote {len(written)} files to {out.as_posix()}", [p.as_posix() for p in written]
    )
    lines += f.close(f"Next: posturanet fix {written[0].as_posix()} --dry-run")
    _framed(f, lines)


@findings_app.command("pull-plans", epilog=_examples(
    ("posturanet findings pull-plans --out plans.json --region us-east-1", "read-only; uses your AWS credentials"),  # noqa: E501 (copyable example)
    ("posturanet findings pull-plans --priority Critical --max 10", "only the most urgent"),
))  # fmt: skip
def findings_pull_plans(
    out: Annotated[Path, typer.Option("--out", help="File to write the plans to.")] = Path(
        "plans.json"
    ),
    repo: RepoOpt = Path("."),
    region: Annotated[str | None, typer.Option(help="AWS Region (default: config).")] = None,
    max_plans: Annotated[int, typer.Option("--max", min=1, max=500, help="Most plans.")] = 25,
    priority: Annotated[
        str | None, typer.Option(help="Only this priority: Critical, High, Medium or Low.")
    ] = None,
) -> None:
    """Read Security Hub remediation plans (read-only) into a file for `findings list|split`."""
    from datetime import UTC, datetime

    from posturanet.aws.remediation_plans import PRIORITIES, pull_plans
    from posturanet.aws.session import boto3_factory

    try:
        if priority is not None and priority not in PRIORITIES:
            raise UsageError(f"--priority must be one of {', '.join(PRIORITIES)}")
        config, _ = load_config(repo)
        client = boto3_factory(config.aws, region)("securityhub")
        doc = pull_plans(
            client,
            now=datetime.now(UTC),
            region=region or config.aws.region,
            max_plans=max_plans,
            priority=priority,
        )
    except PosturaNetError as exc:
        if isinstance(exc, StageStop):
            detail = [f"  why: {exc.why}"] if exc.why else []
            detail += [f"  -> {step}" for step in exc.next_steps]
            if detail:
                typer.echo("\n".join(detail), err=True)
        raise _fail(exc) from exc
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    n = len(doc["Plans"])
    f = _frame()
    lines = f.open(console.header("findings pull-plans", doc.get("Region") or "", f.style))
    lines += [
        f.step("Read Security Hub remediation plans (read-only)"),
        f.step(f"Wrote {n} remediation plan{'s' if n != 1 else ''} to {out}", token="success"),
        f.bar(),
    ]
    lines += f.close(f"Next: posturanet findings list {out} --all")
    _framed(f, lines)


def _finding_row(e: Entry, result: tuple[str, str | None]) -> dict[str, object]:
    f = e.finding
    kind, note = result
    if kind == "none" and not note:
        note = e.reason or (None if e.fixable else "no fix for this control yet")
    return {
        "index": e.index,
        "outcome": kind,
        "finding_id": f.finding_id if f else None,
        "control": e.control_id or "-",
        "fix": f.fix_type.value if f else "-",
        "severity": f.severity.value if f else "-",
        "resource": f.resource.id if f else None,
        "reason": note,
    }


@app.command(epilog=_examples(
    ("posturanet verify owner/repo#123 --repo infra/", "after merge: did the fix hold?"),
    ("posturanet verify owner/repo#123 --repo infra/ --open-pr", "also open a revert PR if it regressed"),  # noqa: E501 (copyable example)
))  # fmt: skip
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


@app.command(epilog=_examples(
    ("posturanet init > policy.json", "save the policy, then attach it to PosturaNet's role"),
))  # fmt: skip
def init() -> None:
    """Print the read-only IAM policy for PosturaNet's role. Writes nothing."""
    _banner(sys.stderr)  # stderr, so `posturanet init > policy.json` stays clean JSON
    console.write(json.dumps(iam_policy(), indent=2) + "\n")


@app.command(epilog=_examples(
    ("pip install \"posturanet[mcp]\"", "once, on the machine the agent runs on"),
    ("posturanet connect cursor --write", "add the MCP server and rule to your repo"),
))  # fmt: skip
def mcp() -> None:
    """Run the read-only MCP server over stdio."""
    try:
        from posturanet.mcp.server import serve
    except ImportError as exc:
        typer.echo("error: install the MCP extra: pip install 'posturanet[mcp]'", err=True)
        raise typer.Exit(2) from exc
    serve()


@app.command(epilog=_examples(
    ("posturanet connect", "every scanner, agent and CI PosturaNet works with"),
    ("posturanet connect prowler", "how to feed Prowler's findings in"),
    ("posturanet connect cursor --write --repo .", "add the MCP server and rule to this repo"),
    ("posturanet connect github --write --repo .", "add the PR check workflow"),
))  # fmt: skip
def connect(
    target: Annotated[
        str | None, typer.Argument(help="A scanner, agent or CI name; omit to list them all.")
    ] = None,
    write: Annotated[
        bool,
        typer.Option("--write", help="Copy the agent or CI files into --repo (never overwrites)."),
    ] = False,
    repo: RepoOpt = Path("."),
    ascii_mode: AsciiOpt = False,
) -> None:
    """Connect your scanner, coding agent or CI to PosturaNet."""
    from posturanet.connect import BY_NAME, TARGETS
    from posturanet.connect import write as write_files

    f = _frame(ascii_mode)
    if target is None:
        lines = f.open(console.header("connect", "", f.style))
        width = max(len(t.name) for t in TARGETS)
        for kind, title in (("scanner", "Scanners"), ("agent", "Coding agents"), ("ci", "CI")):
            rows = [
                f"{f.style('accent', t.name.ljust(width))}  {t.summary}"
                for t in TARGETS
                if t.kind == kind
            ]
            lines += f.box(title, rows)
        lines += f.close("Next: posturanet connect <name>")
        _framed(f, lines)
        raise typer.Exit(0)
    t = BY_NAME.get(target.lower())
    if t is None:
        typer.echo(f"error: unknown target {target!r}; one of: {', '.join(BY_NAME)}", err=True)
        raise typer.Exit(2)
    lines = f.open(console.header("connect", t.name, f.style))
    lines += [f.step(t.summary, info=True), f.bar()]
    lines += f.box("Steps", [f"{i}. {s}" for i, s in enumerate(t.steps, 1)])
    if write:
        if not t.files:
            typer.echo(f"error: {t.name} has no files to write; follow the steps", err=True)
            raise typer.Exit(2)
        if not repo.is_dir():
            raise _fail(UsageError(f"--repo not found: {repo}"))
        results = write_files(t, repo)
        lines += f.box(f"Files in {repo.as_posix()}", [f"{d}  {how}" for d, how in results])
        lines += f.close("Done. Review the files, then commit them.")
    elif t.files:
        lines += f.box("Files --write adds", [dest for _, dest in t.files])
        lines += f.close(f"Next: posturanet connect {t.name} --write --repo .")
    else:
        lines += f.close("Done.")
    _framed(f, lines)


def main() -> None:
    app()
