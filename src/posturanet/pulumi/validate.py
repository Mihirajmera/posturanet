"""Diffs to Pulumi program source and their validation (FR-21..FR-26).

The fix edits only literals in the program, in the file's own style. Validation is static:
the edited files are re-read, only the target's constructor calls changed, the literals give
exactly the synthesized rules (or BLOCK, or the kept actions), the CloudFormation re-check,
contract and invariant checks pass on them, and the stack export shows no drift.
`pulumi preview` is not run: it signs in to the state backend and configures the AWS provider
with the stack's own credentials, which can write. The PR's checks table says so.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

from posturanet.cdk import source as cdk_source
from posturanet.cdk.source import BY_HAND, Construct, SourceStatement, line_start, render_actions
from posturanet.cfn.validate import Checks, iam_checks, s3_checks, sg_checks
from posturanet.errors import StageStop
from posturanet.iamfix.shrink import ServiceUse, StatementChange
from posturanet.models import (
    BehaviorContract,
    Check,
    CheckResult,
    Config,
    Diff,
    FileChange,
    ValidationReport,
)
from posturanet.pulumi import model, yaml_source
from posturanet.pulumi.model import FLAGS, Entry, View, is_open
from posturanet.pulumi.source import Edits, Lit, arg_key, props, render, rescan
from posturanet.pulumi.stack import SG_INGRESS, SG_RULE, PulumiTarget
from posturanet.synth.hcl_render import DEFAULT_DESCRIPTION, unified_diff
from posturanet.synth.sg_rules import WORLD, Rule
from posturanet.synth.sg_z3 import Synthesis
from posturanet.validate.guardrails import check_paths

PREVIEW_NOTE = (
    "not run: `pulumi preview` signs in to the state backend and configures the AWS provider "
    "with the stack's own credentials, which can write; validated statically against the "
    "stack export instead"
)


def _hand(why: str) -> StageStop:
    return StageStop("fix", why, [BY_HAND], unknown=True)


def _rel(path: Path, repo: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def _diff(
    repo: Path, t: PulumiTarget, edits: dict[Path, tuple[Construct, str]], summary: str, gen: str
) -> Diff:
    files, udiffs = [], []
    for path in sorted(edits):
        c, new = edits[path]
        rel = _rel(path, repo)
        udiff = unified_diff(rel, c.text, new)
        udiffs.append(udiff)
        files.append(FileChange(path=rel, unified_diff=udiff, new_content=c.on_disk(new)))
    return Diff(
        target_address=t.address,
        files=files,
        summary=summary,
        generator=gen,
        sha256=hashlib.sha256("".join(udiffs).encode("utf-8")).hexdigest(),
    )


# --- security groups


def _covers(e: Entry, r: Rule) -> bool:
    return any(
        o.proto == "-1"
        or (o.proto == r.proto and o.from_port <= r.from_port <= r.to_port <= o.to_port)
        for o in e.rules
        if str(o.net) in WORLD
    )


def _q(c: Construct, quote: str, text: str) -> str:
    q = quote or '"'
    return ("'" if q == '"' else '"') if q in text else q


def _ingress_item(c: Construct, item: Lit, r: Rule, desc: str | None, quote: str) -> str:
    """One inline ingress entry for `r`, in the shape of the entry it replaces."""
    lo, hi = (0, 0) if r.proto == "-1" else (r.from_port, r.to_port)
    key = "cidrBlocks" if r.net.version == 4 else "ipv6CidrBlocks"
    vals: dict[str, object] = {"protocol": r.proto, "fromPort": lo, "toPort": hi, key: [r.cidr]}
    if desc:
        vals["description"] = desc
    if c.lang == "yaml":  # a copy of the entry it replaces, with these values
        return yaml_source.edit_item(c.text, item, vals)
    q = _q(c, quote, desc or "")
    if item.call:  # Python `…SecurityGroupIngressArgs(` call
        return (
            f"{item.call}("
            + ", ".join(f"{arg_key(c, k)}={render(v, c, q)}" for k, v in vals.items())
            + ")"
        )
    return render(vals, c, q, py_keys=True)


def _list_edits(c: Construct, lst: Lit, new: dict[int, list[str]]) -> list[tuple[int, int, str]]:
    """Replace items of a list literal (by index) with zero or more items, in its layout."""
    its: list[Lit] = lst.value
    gone = {i for i, v in new.items() if not v}
    if len(gone) == len(its):
        return [(lst.span[0], lst.span[1], "[]")]
    out = []
    k = max(i for i in range(len(its)) if i not in gone)
    for i, texts in new.items():
        s, e = its[i].span
        if texts:
            indent = c.text[line_start(c.text, s) : s]
            sep = (
                ",\n" + indent if not indent.strip() and "\n" in c.masked[lst.span[0] : s] else ", "
            )
            if c.lang == "yaml" and lst.brackets is None:  # a block list: `- ` items
                sep = yaml_source.item_sep(c.text, its[i])
            out.append((s, e, sep.join(texts)))
        elif i < k:
            out.append((s, its[i + 1].span[0], ""))
    trailing = sorted(i for i in gone if i > k)
    if trailing:
        out.append((its[k].span[1], its[trailing[-1]].span[1], ""))
    return out


def _standalone_edit(
    t: PulumiTarget, v: View, e: Entry, rules: list[Rule]
) -> list[tuple[int, int, str]]:
    part = t.parts()[e.index]
    name, c, p = part.state.name, v.constructs[e.index], v.props[e.index]
    ports = {(r.proto, r.from_port, r.to_port) for r in [*e.rules, *rules]}
    if len(ports) != 1:
        raise _hand(
            f"the fix needs other ports than ingress rule '{name}' has; one resource holds "
            "one port range and PosturaNet won't add resources"
        )
    if not rules:
        raise _hand(f"the fix removes every CIDR of ingress rule '{name}'; delete it by hand")
    v4 = [r.cidr for r in rules if r.net.version == 4]
    v6 = [r.cidr for r in rules if r.net.version == 6]
    q = e.quote if c.lang == "yaml" else e.quote or '"'
    out: list[tuple[int, int, str]] = []
    if part.state.type == SG_INGRESS:
        key = "cidrIpv4" if v4 else "cidrIpv6"
        lit = p.values.get(key)
        if len(rules) != 1 or lit is None or lit.kind != "str":
            raise _hand(
                f"the fix needs {len(rules)} CIDRs in '{name}', which holds one; "
                "PosturaNet won't add resources"
            )
        return [(lit.span[0], lit.span[1], render(rules[0].cidr, c, q))]
    assert part.state.type == SG_RULE
    for key, cidrs in (("cidrBlocks", v4), ("ipv6CidrBlocks", v6)):
        lit = p.values.get(key)
        if lit is not None:
            new = (
                yaml_source.list_text(c.text, lit, cidrs)
                if c.lang == "yaml" and lit.kind == "list"
                else render(cidrs, c, q)
            )
            out.append((lit.span[0], lit.span[1], new))
        elif cidrs:
            raise _hand(f"ingress rule '{name}' has no {key} to put {cidrs[0]} in")
    return out


def sg_diff(repo: Path, t: PulumiTarget, synth: Synthesis) -> Diff:
    v = t.view()
    open_entries = [e for e in v.entries if is_open(e.rules)]
    given: dict[int, list[Rule]] = {id(e): [] for e in open_entries}
    for r in synth.added:
        home = next((e for e in open_entries if _covers(e, r)), None)
        if home is None:
            raise _hand(f"no open ingress entry covers {r.label()}")
        given[id(home)].append(r)
    by_file: dict[Path, Edits] = {}
    inline: dict[int, list[str]] = {}
    for e in open_entries:
        keep = [r for r in e.rules if str(r.net) not in WORLD]
        c = v.constructs[e.index]
        edits = by_file.setdefault(c.file, Edits(c))
        if e.lit is None:
            edits.spans += _standalone_edit(t, v, e, sorted({*keep, *given[id(e)]}))
            continue
        inline[v.entries.index(e)] = [
            _ingress_item(c, e.lit, r, e.description, e.quote) for r in keep
        ] + [
            _ingress_item(c, e.lit, r, e.description or DEFAULT_DESCRIPTION, e.quote)
            for r in given[id(e)]
        ]
    if inline:
        assert v.ingress is not None
        c = v.constructs[0]
        by_file.setdefault(c.file, Edits(c)).spans += _list_edits(c, v.ingress, inline)
    edited = {p: (ed.c, ed.apply()) for p, ed in by_file.items()}
    before = [r.label() for r in synth.removed]
    after = [r.label() for r in synth.added]
    summary = (
        f"{', '.join(before)} → {', '.join(after)} ({len(after)} rule{'s' * (len(after) != 1)})"
        if after
        else f"remove {', '.join(before)}"
    )
    diff = _diff(repo, t, edited, summary, "template:sg_ingress@1:pulumi")
    return diff.model_copy(update={"rules_before": before, "rules_after": after})


# --- S3 Block Public Access


def s3_diff(repo: Path, t: PulumiTarget) -> Diff:
    v = t.view()
    c = v.constructs[0]
    name = t.state.name
    off = [f for f in FLAGS if not (v.flags[f] and v.flags[f].value)]  # type: ignore[union-attr]
    if not off:
        raise StageStop(
            "fix",
            f"the code already sets every flag of '{name}' to true, so the finding is stale "
            "or the bucket drifted after the export",
            ["export the stack again after `pulumi refresh` and re-run"],
            why="PosturaNet fixes code, and this code is already fixed",
        )
    text = Edits(
        c, [(lit.span[0], lit.span[1], render(True, c, "")) for f in off if (lit := v.flags[f])]
    ).apply()
    for f in off:
        if v.flags[f] is not None:
            continue
        c = rescan(c, text)
        if c.lang == "yaml":
            text = yaml_source.add_key(c, f, "true")
            continue
        brackets = props(c).brackets
        if brackets is None:
            raise _hand(f"'{name}' has no arguments object to add {f} to")
        item = f"{f}: true" if c.lang == "ts" else f"{arg_key(c, f)}=True"
        text = cdk_source.append_item(c.text, c.masked, brackets, item)
    summary = f"{name}: {', '.join(off)} → true"
    return _diff(repo, t, {c.file: (v.constructs[0], text)}, summary, "template:s3_public@1:pulumi")


# --- IAM policies


def iam_diff(repo: Path, t: PulumiTarget, changes: list[StatementChange]) -> Diff:
    v = t.view()
    c = v.constructs[0]
    spans: list[tuple[int, int, str]] = []
    for ch in changes:
        lit = v.statements[ch.statement.index].value.get("Action")
        if lit is None:
            raise _hand(f"statement {ch.statement.index + 1} has no literal Action")
        if lit.kind == "list" and all(x.kind == "str" for x in lit.value) and c.lang == "yaml":
            spans.append((lit.span[0], lit.span[1], yaml_source.list_text(c.text, lit, ch.after)))
        elif lit.kind == "list" and all(x.kind == "str" for x in lit.value):
            q = lit.value[0].quote if lit.value else '"'
            st = SourceStatement([x.value for x in lit.value], lit.span, q)
            spans.append((lit.span[0], lit.span[1], render_actions(c, st, ch.after)))
        elif lit.kind == "str":
            new = ch.after[0] if len(ch.after) == 1 else ch.after
            spans.append((lit.span[0], lit.span[1], render(new, c, lit.quote)))
        else:
            raise _hand(f"statement {ch.statement.index + 1} Action is not a literal")
    removed = sorted({p for ch in changes for p in ch.removed})
    kept = sum(len(ch.after) for ch in changes)
    summary = f"{', '.join(removed)} → {kept} used action(s) in {len(changes)} statement(s)"
    diff = _diff(
        repo, t, {c.file: (c, Edits(c, spans).apply())}, summary,
        "template:iam_least_privilege@1:pulumi",
    )  # fmt: skip
    return diff.model_copy(
        update={
            "rules_before": [a for ch in changes for a in ch.before],
            "rules_after": [a for ch in changes for a in ch.after],
        }
    )


# --- validation

SourceCheck = Callable[[View], tuple[bool, str, str]]


def _gaps(text: str, spans: list[tuple[int, int]]) -> list[str]:
    out, pos = [], 0
    for s, e in sorted(spans):
        out.append(text[pos:s])
        pos = e
    return [*out, text[pos:]]


def _scope(t: PulumiTarget, v: View) -> Check:
    """Every edited file is the same outside the target's constructor calls, and those calls
    still name the same resources (re-scanned by name and class)."""
    bad = []
    for path in {c.file for c in v.constructs}:
        old = [p.construct for p in t.parts() if p.construct.file == path]
        new = [c for c in v.constructs if c.file == path]
        old_gaps = _gaps(old[0].text, [(c.start, c.close + 1) for c in old])
        if old_gaps != _gaps(new[0].text, [(c.start, c.close + 1) for c in new]):
            bad.append(path.name)
    ok = not bad
    return Check(
        id="program_scope",
        required=True,
        result=CheckResult.PASS if ok else CheckResult.FAIL,
        detail=f"only the arguments of '{t.state.name}'"
        + (f" and {len(t.rules)} ingress rule(s)" if t.rules else "")
        + " change"
        if ok
        else "the edit changes code outside the target in " + ", ".join(sorted(bad)),
    )


def drift_check(t: PulumiTarget) -> Check:
    why = model.drift(t.state.type, t.parts())
    return Check(
        id="drift",
        required=True,
        result=CheckResult.PASS if why is None else CheckResult.FAIL,
        detail=f"inputs match outputs in {t.label} (no refresh run)" if why is None else why,
    )


def _validate(
    repo: Path, t: PulumiTarget, diff: Diff, config: Config, source: SourceCheck, specific: Checks
) -> ValidationReport:
    checks = [check_paths(diff, config.validation.allowed_paths, config.contracts.dir)]
    texts = {repo / f.path: f.new_content.replace("\r\n", "\n") for f in diff.files}
    known = {p.construct.file for p in t.parts()}
    if any(p not in known for p in texts):
        checks.append(
            Check(
                id="program_scope",
                required=True,
                result=CheckResult.FAIL,
                detail="the diff touches a file that defines none of the target's resources",
            )
        )
    try:
        v = t.view(texts)
        ok, yes, no = source(v)
        checks.append(
            Check(
                id="source",
                required=True,
                result=CheckResult.PASS if ok else CheckResult.FAIL,
                detail=yes if ok else no,
            )
        )
        checks.append(_scope(t, v))
        edited = model.resource(t.state.type, v, t.state.stack, t.state.name, v.constructs[0])
        checks += specific(edited)
    except StageStop as exc:
        checks.append(Check(id="source", required=True, result=CheckResult.FAIL, detail=exc.reason))
    checks.append(drift_check(t))
    checks.append(
        Check(id="pulumi_preview", required=False, result=CheckResult.SKIPPED, detail=PREVIEW_NOTE)
    )
    return ValidationReport(checks=checks)


def validate_sg(
    repo: Path,
    t: PulumiTarget,
    diff: Diff,
    synth: Synthesis,
    contract: BehaviorContract,
    control: str,
    config: Config,
) -> ValidationReport:
    expected = sorted({cdk_source.norm(r) for r in [*synth.kept, *synth.added]})

    def source(v: View) -> tuple[bool, str, str]:
        return (
            v.rules == expected,
            "edited literals have exactly the synthesized rules",
            "edited literals' rules differ from the synthesized rules",
        )

    return _validate(repo, t, diff, config, source, sg_checks(synth, contract, control))


def validate_s3(
    repo: Path, t: PulumiTarget, diff: Diff, control: str, config: Config
) -> ValidationReport:
    def source(v: View) -> tuple[bool, str, str]:
        ok = all(lit is not None and lit.value is True for lit in v.flags.values())
        return ok, "edited literals set all 4 flags to true", "a flag is still not true"

    return _validate(repo, t, diff, config, source, s3_checks(control))


def validate_iam(
    repo: Path,
    t: PulumiTarget,
    diff: Diff,
    control: str,
    changes: list[StatementChange],
    usage: dict[str, ServiceUse],
    extra: list[str],
    config: Config,
) -> ValidationReport:
    before = [s.get("Action") for s in t.view().doc["Statement"]]
    for ch in changes:
        before[ch.statement.index] = ch.after

    def source(v: View) -> tuple[bool, str, str]:
        ok = [s.get("Action") for s in v.doc["Statement"]] == before
        return ok, "edited statements have exactly the kept actions", "edited actions differ"

    return _validate(repo, t, diff, config, source, iam_checks(control, changes, usage, extra))
