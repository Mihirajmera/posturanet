"""PR title, body and labels (design system section 6)."""

from __future__ import annotations

import io
from typing import Any

from ruamel.yaml import YAML

from posturanet import __version__
from posturanet.deliver.idempotency import markers, verify_marker
from posturanet.evidence.periodicity import describe
from posturanet.models import CheckResult, VerifySpec
from posturanet.proposal import Proposal
from posturanet.validate.invariants import MODEL_SCOPE

PORT_NAMES = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "Postgres",
    1433: "SQL Server",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
_WATCH_WINDOW = "72h"
_CHECK_LABELS = {
    "guardrails": "guardrails",
    "fmt": "fmt",
    "validate": "validate",
    "plan_scope": "plan scope",
    "drift": "drift",
    "plan_matches": "plan matches fix",
    "invariants": "contract invariants",
    "recheck": "finding re-check",
}


def short_name(p: Proposal) -> str:
    if p.location.module_path:
        return p.location.module_path[-1]
    return p.location.address.rsplit(".", 1)[-1]


def title(p: Proposal) -> str:
    ports = sorted({r.from_port for r in p.synthesis.removed if r.from_port == r.to_port})
    what = PORT_NAMES.get(ports[0], f"port {ports[0]}") if len(ports) == 1 else "open"
    verb = "restrict" if p.synthesis.added else "remove"
    text = f"🔒 PosturaNet: {verb} {what} ingress on {short_name(p)} SG ({p.finding.control_id})"
    if len(text) > 72:
        text = f"🔒 PosturaNet: {verb} {what} ingress ({p.finding.control_id})"
    return text[:72]


def labels(p: Proposal, base: list[str]) -> list[str]:
    out = list(dict.fromkeys([*base, "posturanet", f"risk:{p.risk}"]))
    if p.needs_review:
        out.append("needs-review")
    return out


def _sym(result: CheckResult) -> str:
    return {
        CheckResult.PASS: "✓ PASS",
        CheckResult.FAIL: "✗ FAIL",
        CheckResult.ERROR: "? ERROR",
        CheckResult.SKIPPED: "SKIPPED",
    }[result]


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def safety_contract(p: Proposal) -> dict[str, Any]:
    f, loc, obs = p.finding, p.location, p.observations
    return {
        "finding": f"{f.source}/{f.control_id} {f.resource.id}",
        "resource": f"{loc.address}  # {loc.file}:{loc.line}",
        "owner": ", ".join(loc.owners) or None,
        "evidence": {
            "source": obs.source,
            "window": f"{obs.window.days}d",
            "confidence": obs.confidence.value,
        },
        "change": p.diff.summary,
        "preconditions": [
            "no drift on target",
            f"flow logs coverage >= {int(obs.window.coverage_ratio * 100)}%",
        ],
        "invariants": [
            {"id": c.id, "result": c.result.value.upper(), "method": _method(c.id)}
            for c in p.report.checks
            if c.required
        ],
        "disruption": p.disruption,
        "risk": p.risk,
        "residual_risk": [p.contract.unknown_risk] if p.contract.unknown_risk else [],
        "unknowns": p.unknowns,
        "post_merge": {
            "recheck": True,
            "watch": "flowlog_reject_from_must_allow",
            "window": _WATCH_WINDOW,
            "on_regression": "revert_pr",
        },
        "status": "VALIDATED" if p.validated else p.report.status.value,
        "model_scope": MODEL_SCOPE,
    }


def verify_spec(p: Proposal) -> VerifySpec:
    rules = sorted({*p.synthesis.kept, *p.synthesis.added})
    return VerifySpec(
        fix_type=p.finding.fix_type.value,
        control=p.finding.control_id,
        finding_id=p.finding.finding_id,
        resource_id=p.finding.resource.id,
        resource_arn=p.finding.resource.arn,
        address=p.location.address,
        key=p.idempotency_key,
        watch_hours=int(_WATCH_WINDOW.rstrip("h")),
        rules=[(r.cidr, r.from_port, r.to_port, r.proto) for r in rules],
        must_allow=[(r.cidr, r.port, r.proto) for r in p.contract.must_allow],
    )


def _method(check_id: str) -> str:
    return {
        "invariants": "z3",
        "plan_scope": "terraform-plan",
        "plan_matches": "terraform-plan",
        "drift": "terraform-plan",
        "recheck": "check",
        "fmt": "terraform-fmt",
        "validate": "terraform-validate",
    }.get(check_id, "static")


def _yaml(data: dict[str, Any]) -> str:
    y = YAML()
    y.default_flow_style = None
    y.width = 200
    buf = io.StringIO()
    y.dump(data, buf)
    return buf.getvalue().rstrip()


def body(p: Proposal, *, run_id: str) -> str:
    f, loc, obs = p.finding, p.location, p.observations
    owners = ", ".join(loc.owners) if loc.owners else "unknown (no CODEOWNERS match)"
    kept_cidrs = [r.label() for r in p.synthesis.added]
    plain = (
        f"Replaces {', '.join(r.label() for r in p.synthesis.removed)} with "
        f"{len(kept_cidrs)} rule{'s' * (len(kept_cidrs) != 1)} that keep every source seen in the "
        f"last {obs.window.days} days."
        if kept_cidrs
        else f"Removes {', '.join(r.label() for r in p.synthesis.removed)}. No traffic used it "
        f"in the last {obs.window.days} days."
    )
    if p.contract.not_kept:
        n = len(p.contract.not_kept)
        plain = plain.replace(
            "days.", f"days, except {n} likely scanner{'s' * (n != 1)} (listed below)."
        ).replace("No traffic used it", "Only likely scanners used it")
    diff_text = "\n".join(fc.unified_diff.rstrip() for fc in p.diff.files)

    observed_rows = []
    review_set = {(r.cidr, r.port, r.proto) for r in p.contract.needs_review}
    dropped = {(r.cidr, r.port, r.proto): r.reason for r in p.contract.not_kept}
    for item in obs.items:
        key = (item.cidr, item.port, item.proto)
        pattern = describe(item.period, item.hours_histogram).replace("@", " at ")
        pattern = pattern.replace(":00Z", ":00 UTC")
        if key in review_set:
            pattern += " · needs review"
        kept = "✓"
        if key in dropped:
            pattern += f" · not kept: {dropped[key]}"
            kept = "✗"
        observed_rows.append(
            f"| {item.cidr} | {item.port}/{item.proto} | {item.count:,} | {pattern} | {kept} |"
        )

    check_rows = [
        f"| {_CHECK_LABELS.get(c.id, c.id)} | {_sym(c.result)} | {_cell(c.detail)} |"
        for c in p.report.checks
    ]
    unknowns = [p.contract.unknown_risk, *p.unknowns] if p.contract.unknown_risk else p.unknowns
    unknown_lines = [f"- {u}" for u in unknowns] or ["- None identified"]

    parts = [
        markers(p.idempotency_key, p.issue),
        verify_marker(verify_spec(p)),
        f"**PosturaNet** found a fix for **{f.control_id} · {f.title}** and checked it "
        "against real usage.",
        "",
        "| | |",
        "|---|---|",
        f"| Resource | `{loc.address}` · `{loc.file}:{loc.line}` |",
        f"| Owner | {owners} |",
        f"| Risk / disruption | {p.risk} / {p.disruption} |",
        f"| Evidence | {obs.source} · {obs.window.days} days · confidence "
        f"**{obs.confidence.value}** |",
        "",
        "### What changes",
        plain,
        "",
        "```diff",
        diff_text,
        "```",
        "",
        "### What's using this resource (observed)",
        "| Source | Port | Connections | Pattern | Kept? |",
        "|---|---|---|---|---|",
        *(observed_rows or ["| none observed | | | | |"]),
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
        "- [ ] Confirm the owners of any **needs review** source.",
        f"- [ ] Review `{p.contract_file}`. Merging approves it as the behavior contract.",
        "- [ ] Merge to apply through your normal pipeline. PosturaNet never applies changes.",
        "",
        "### After merge",
        "`posturanet verify <this PR>` re-checks the finding and watches for blocked traffic "
        f"from kept sources for **{_WATCH_WINDOW}**. If it sees a regression, it opens a "
        "revert PR.",
        "",
        "<details><summary>Safety contract (machine-readable)</summary>",
        "",
        "```yaml",
        _yaml(safety_contract(p)),
        "```",
        "</details>",
        "",
        f"<sub>PosturaNet {__version__} · run {run_id} · evidence and checks describe the tested "
        "conditions and modeled scope; they are not a guarantee of production behavior.</sub>",
    ]
    return "\n".join(parts) + "\n"
