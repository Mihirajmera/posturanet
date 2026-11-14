"""PR title, body and labels for S3 public-access fixes (design system section 6, FR-50)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from posturanet import __version__
from posturanet.configfix.catalog import ConfigFix
from posturanet.deliver.idempotency import issue, markers, verify_marker
from posturanet.deliver.pr_body import _CHECK_LABELS, _cell, _sym
from posturanet.models import Diff, Finding, Location, ValidationReport, VerifySpec
from posturanet.models.s3 import S3Evidence
from posturanet.s3fix import S3Target

_LABELS = {**_CHECK_LABELS, "plan_matches": "plan matches fix"}
_SOURCE = {
    "s3_access_logs": "S3 server access logs",
    "s3_evidence_file": "S3 evidence (file)",
    "s3_config": "bucket configuration",
}


@dataclass
class S3Proposal:
    finding: Finding
    location: Location  # the bucket (or, for S3.1, the account block's file)
    target: S3Target
    fix: ConfigFix
    evidence: S3Evidence
    diff: Diff
    report: ValidationReport
    contract_file: str
    already: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    @property
    def issue(self) -> str:
        return issue(self.fix.control, self.location.address)

    @property
    def idempotency_key(self) -> str:
        text = self.issue + self.diff.sha256
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @property
    def risk(self) -> str:
        return "low" if self.evidence.window_days == 0 else "medium"

    @property
    def disruption(self) -> str:
        if self.evidence.window_days == 0:
            return "none expected: nothing is public today"
        return "none expected: no public use in the logs"


def verify_spec(p: S3Proposal) -> VerifySpec:
    return VerifySpec(
        fix_type=p.finding.fix_type.value,
        control=p.fix.control,
        finding_id=p.finding.finding_id,
        resource_id=p.finding.resource.id,
        resource_arn=p.finding.resource.arn,
        address=p.target.address,
        key=p.idempotency_key,
        # Denied anonymous requests after the fix can't be told apart from scanners, and the
        # evidence already showed no public use, so there is no traffic signal to watch.
        watch_hours=0,
        changes=[c.model_dump() for c in p.fix.changes],
    )


def _short(p: S3Proposal) -> str:
    return p.target.bucket or "account"


def branch(p: S3Proposal) -> str:
    short = _short(p).replace("_", "-").replace(".", "-").lower()[:30]
    return (
        f"posturanet/s3/{p.fix.control.replace('.', '-').lower()}-{short}-{p.idempotency_key[:8]}"
    )


def title(p: S3Proposal) -> str:
    where = p.target.bucket or "the account"
    text = f"🔒 PosturaNet: block public access on {where} ({p.fix.control})"
    if len(text) > 72:
        text = f"🔒 PosturaNet: block public access on an S3 bucket ({p.fix.control})"
    return text[:72]


def labels(p: S3Proposal, base: list[str]) -> list[str]:
    return list(dict.fromkeys([*base, "posturanet", f"risk:{p.risk}"]))


def _evidence_rows(ev: S3Evidence) -> list[str]:
    rows = [f"- {ev.basis}."]
    for b in ev.buckets:
        e = b.exposure
        flags = [
            name
            for name, on in (
                ("public policy", e.policy_public),
                ("public ACL", e.acl_public),
                ("ACLs enabled", e.acls_enabled),
                ("website", e.website),
            )
            if on
        ]
        if ev.scope == "bucket" or flags:
            rows.append(f"- `{b.bucket}`: {', '.join(flags) or 'private, ACLs disabled'}")
        for u in b.keeps[:8]:
            rows.append(
                f"  - keeps working: `{u.requester}` ({u.kind.replace('_', '-')}), "
                f"{u.count:,} requests, last {u.last_seen}"
            )
        for o in b.cloudfront:
            how = "origin access control" if o.private else "public origin"
            rows.append(f"  - CloudFront {o.distribution}: {how}")
    return rows


def body(p: S3Proposal, *, run_id: str) -> str:
    f, loc, ev = p.finding, p.location, p.evidence
    owners = ", ".join(loc.owners) if loc.owners else "unknown (no CODEOWNERS match)"
    diff_text = "\n".join(fc.unified_diff.rstrip() for fc in p.diff.files)
    window = (
        f"{_SOURCE.get(ev.source, ev.source)} · {ev.window_days} days · "
        f"{ev.coverage_ratio:.0%} coverage · confidence {ev.confidence.value}"
        if ev.window_days
        else f"{_SOURCE.get(ev.source, ev.source)} · confidence {ev.confidence.value}"
    )
    checks = [
        f"| {_LABELS.get(c.id, c.id)} | {_sym(c.result)} | {_cell(c.detail)} |"
        for c in p.report.checks
    ]
    unknown_lines = [f"- {u}" for u in p.unknowns] or ["- None identified"]
    what = "adds a public access block" if p.target.action == "create" else "turns on"
    parts = [
        markers(p.idempotency_key, p.issue),
        verify_marker(verify_spec(p)),
        f"**PosturaNet** found a fix for **{f.control_id} · {f.title or p.fix.title}**. It "
        f"{what} all four S3 Block Public Access settings and changes nothing else.",
        "",
        "| | |",
        "|---|---|",
        f"| Resource | `{p.target.address}` · `{p.target.file}:{p.target.line}` |",
        f"| Owner | {owners} |",
        f"| Risk / disruption | {p.risk} / {p.disruption} |",
        f"| Evidence | {window} |",
        f"| Contract | `{p.contract_file}` |",
        "",
        "### Evidence",
        *_evidence_rows(ev),
        "",
        "### What changes",
        f"{p.diff.summary}. {p.fix.why}",
        *([""] + [f"- `{a}` (already set in code)" for a in p.already] if p.already else []),
        "",
        "```diff",
        diff_text,
        "```",
        "",
        "### Checks",
        "| Check | Result | Detail |",
        "|---|---|---|",
        *checks,
        "",
        "### Unknowns and residual risk",
        *unknown_lines,
        "",
        "### Before you merge",
        "- [ ] Check `must_keep` in the contract lists everyone who should keep access.",
        "- [ ] Check the plan in CI shows only this resource changing.",
        "- [ ] Merge to apply through your normal pipeline. PosturaNet never applies changes.",
        "",
        "### After merge",
        f"After apply, `posturanet verify <this PR>` checks the state and confirms "
        f"{p.fix.control} passes.",
        "",
        f"<sub>PosturaNet {__version__} · run {run_id} · checks describe the observed signals "
        "and tested conditions; they are not a guarantee of production behavior.</sub>",
    ]
    return "\n".join(parts) + "\n"
