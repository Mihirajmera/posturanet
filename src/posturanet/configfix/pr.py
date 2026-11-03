"""PR title, body and labels for attribute fixes (design system section 6, FR-48)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from posturanet import __version__
from posturanet.configfix.catalog import ConfigFix
from posturanet.deliver.idempotency import markers
from posturanet.deliver.pr_body import _CHECK_LABELS, _cell, _sym
from posturanet.models import Diff, Finding, Location, ValidationReport

_CHECK_LABELS_CONFIG = {**_CHECK_LABELS, "plan_matches": "plan matches fix"}


@dataclass
class ConfigProposal:
    finding: Finding
    location: Location
    fix: ConfigFix
    diff: Diff
    report: ValidationReport
    already: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    @property
    def idempotency_key(self) -> str:
        text = self.finding.finding_id + self.fix.control + self.diff.sha256
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @property
    def risk(self) -> str:
        return self.fix.risk

    @property
    def disruption(self) -> str:
        return "none expected" if self.fix.risk == "low" else "possible; see note"


def short_name(p: ConfigProposal) -> str:
    if p.location.module_path:
        return p.location.module_path[-1]
    return p.location.address.rsplit(".", 1)[-1].split("[", 1)[0]


def branch(p: ConfigProposal) -> str:
    short = short_name(p).replace("_", "-").lower()
    control = p.fix.control.replace(".", "-").lower()
    return f"posturanet/config/{control}-{short}-{p.idempotency_key[:8]}"


def title(p: ConfigProposal) -> str:
    names = ", ".join(dict.fromkeys(c.name for c in p.fix.changes))
    text = f"🔒 PosturaNet: set {names} on {short_name(p)} ({p.fix.control})"
    if len(text) > 72:
        text = f"🔒 PosturaNet: update settings on {short_name(p)} ({p.fix.control})"
    if len(text) > 72:
        text = f"🔒 PosturaNet: update settings ({p.fix.control})"
    return text[:72]


def labels(p: ConfigProposal, base: list[str]) -> list[str]:
    out = list(dict.fromkeys([*base, "posturanet", f"risk:{p.risk}"]))
    if p.fix.risk != "low":
        out.append("needs-review")
    return out


def body(p: ConfigProposal, *, run_id: str) -> str:
    f, loc, fix = p.finding, p.location, p.fix
    owners = ", ".join(loc.owners) if loc.owners else "unknown (no CODEOWNERS match)"
    diff_text = "\n".join(fc.unified_diff.rstrip() for fc in p.diff.files)
    check_rows = [
        f"| {_CHECK_LABELS_CONFIG.get(c.id, c.id)} | {_sym(c.result)} | {_cell(c.detail)} |"
        for c in p.report.checks
    ]
    unknowns = [*p.unknowns]
    if fix.note:
        unknowns.insert(0, fix.note)
    unknown_lines = [f"- {u}" for u in unknowns] or ["- None identified"]
    already = [f"- `{a}` (already set in code)" for a in p.already]

    parts = [
        markers(p.idempotency_key, f.finding_id),
        f"**PosturaNet** found a fix for **{f.control_id} · {f.title or fix.title}**. It changes "
        "settings on one resource and nothing else.",
        "",
        "| | |",
        "|---|---|",
        f"| Resource | `{loc.address}` · `{loc.file}:{loc.line}` |",
        f"| Owner | {owners} |",
        f"| Risk / disruption | {p.risk} / {p.disruption} |",
        "| Evidence | not needed: this setting doesn't remove access or traffic |",
        "",
        "### What changes",
        f"{p.diff.summary}. {fix.why}",
        *([""] + already if already else []),
        "",
        "```diff",
        diff_text,
        "```",
        "",
        "### Checks",
        "| Check | Result | Detail |",
        "|---|---|---|",
        *check_rows,
        "",
        "### Unknowns and residual risk",
        *unknown_lines,
        "",
        "### Before you merge",
        "- [ ] Check the plan in CI shows only this resource changing, in place.",
        "- [ ] Merge to apply through your normal pipeline. PosturaNet never applies changes.",
        "",
        "### After merge",
        f"Re-run `posturanet fix` on the finding after apply to confirm {fix.control} passes.",
        "",
        f"<sub>PosturaNet {__version__} · run {run_id} · checks describe the tested "
        "conditions; they are not a guarantee of production behavior.</sub>",
    ]
    return "\n".join(parts) + "\n"
