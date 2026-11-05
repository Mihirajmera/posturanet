"""PR title, body and labels for IAM least-privilege fixes (design system section 6, FR-51)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from posturanet import __version__
from posturanet.deliver.idempotency import markers, verify_marker
from posturanet.deliver.pr_body import _CHECK_LABELS, _cell, _sym
from posturanet.iamfix.shrink import StatementChange
from posturanet.models import Diff, Finding, Location, ValidationReport, VerifySpec
from posturanet.models.iam import IamEvidence

WATCH_HOURS = 72
_SOURCE = {
    "iam_last_accessed": "IAM last-accessed data",
    "iam_evidence_file": "IAM evidence (file)",
}


@dataclass
class IamProposal:
    finding: Finding
    location: Location
    evidence: IamEvidence
    changes: list[StatementChange]
    diff: Diff
    report: ValidationReport
    contract_file: str
    form: str
    unknowns: list[str] = field(default_factory=list)

    @property
    def idempotency_key(self) -> str:
        text = self.finding.finding_id + self.finding.control_id + self.diff.sha256
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @property
    def removed(self) -> list[str]:
        return sorted({p for c in self.changes for p in c.removed})

    @property
    def risk(self) -> str:
        return "medium"

    @property
    def disruption(self) -> str:
        return "none expected: every used action stays allowed"


def verify_spec(p: IamProposal) -> VerifySpec:
    return VerifySpec(
        fix_type=p.finding.fix_type.value,
        control=p.finding.control_id,
        finding_id=p.finding.finding_id,
        resource_id=p.finding.resource.id,
        resource_arn=p.finding.resource.arn,
        address=p.location.address,
        key=p.idempotency_key,
        watch_hours=WATCH_HOURS,
        actions_removed=p.removed,
        actions_after=sorted({a for c in p.changes for a in c.after}, key=str.lower),
        principals=p.evidence.principals,
    )


def _name(p: IamProposal) -> str:
    return p.finding.resource.id.rsplit("/", 1)[-1]


def branch(p: IamProposal) -> str:
    short = _name(p).replace("_", "-").replace(".", "-").lower()[:30]
    control = p.finding.control_id.replace(".", "-").lower()
    return f"posturanet/iam/{control}-{short}-{p.idempotency_key[:8]}"


def title(p: IamProposal) -> str:
    text = f"🔒 PosturaNet: replace wildcard actions in {_name(p)} ({p.finding.control_id})"
    if len(text) > 72:
        text = f"🔒 PosturaNet: replace wildcard IAM actions ({p.finding.control_id})"
    return text[:72]


def labels(p: IamProposal, base: list[str]) -> list[str]:
    return list(dict.fromkeys([*base, "posturanet", f"risk:{p.risk}", "needs-review"]))


def body(p: IamProposal, *, run_id: str) -> str:
    f, loc, ev = p.finding, p.location, p.evidence
    owners = ", ".join(loc.owners) if loc.owners else "unknown (no CODEOWNERS match)"
    diff_text = "\n".join(fc.unified_diff.rstrip() for fc in p.diff.files)
    checks = [
        f"| {_CHECK_LABELS.get(c.id, c.id)} | {_sym(c.result)} | {_cell(c.detail)} |"
        for c in p.report.checks
    ]
    used = ev.used()
    used_rows = [f"- `{u.action}` · last used {u.last_seen}" for u in used[:15]]
    if len(used) > 15:
        used_rows.append(f"- … {len(used) - 15} more (see the contract)")
    principals = ", ".join(f"`{x}`" for x in ev.principals[:6]) + (
        f" and {len(ev.principals) - 6} more" if len(ev.principals) > 6 else ""
    )
    parts = [
        markers(p.idempotency_key, f.finding_id),
        verify_marker(verify_spec(p)),
        f"**PosturaNet** found a fix for **{f.control_id} · {f.title}**. It replaces "
        f"{', '.join(f'`{r}`' for r in p.removed)} with the actions the attached principals "
        "used, and changes nothing else in the policy.",
        "",
        "| | |",
        "|---|---|",
        f"| Policy | `{loc.address}` · `{p.diff.files[0].path}` ({p.form}) |",
        f"| Attached to | {principals or 'nothing'} |",
        f"| Owner | {owners} |",
        f"| Risk / disruption | {p.risk} / {p.disruption} |",
        f"| Evidence | {_SOURCE.get(ev.source, ev.source)} · policy age {ev.age_days} days · "
        f"confidence {ev.confidence.value} |",
        f"| Contract | `{p.contract_file}` |",
        "",
        "### Used actions kept",
        *(used_rows or ["- none from last-accessed data; only actions listed in the contract"]),
        "",
        "### What changes",
        f"{p.diff.summary}. Resources, conditions and Deny statements are unchanged.",
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
        *([f"- {u}" for u in p.unknowns] or ["- None identified"]),
        "",
        "### Before you merge",
        "- [ ] Check rare jobs (quarterly, yearly, break-glass) are covered; add their actions "
        "to `must_allow` in the contract if not.",
        "- [ ] Merge to apply through your normal pipeline. PosturaNet never applies changes.",
        "",
        "### After merge",
        f"After apply, `posturanet verify <this PR>` checks the state, re-checks {f.control_id} "
        f"and watches CloudTrail for {WATCH_HOURS}h for AccessDenied on the removed actions; "
        "on a regression it opens a revert PR.",
        "",
        f"<sub>PosturaNet {__version__} · run {run_id} · checks describe the observed signals "
        "and tested conditions; they are not a guarantee of production behavior.</sub>",
    ]
    return "\n".join(parts) + "\n"
