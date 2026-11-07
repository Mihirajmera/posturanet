"""Check a change against the behavior contracts in the repo (US-4, US-7, MCP check_change).

Read-only. A change that would break a contract is BLOCK; one PosturaNet can't judge
(computed at apply, non-literal HCL, remote module, unevaluated conditions) is UNKNOWN, never
PASS. Three contract kinds:
- `network` (security groups): must_allow sources stay allowed, must_deny stays denied.
- `s3_public` (S3 Block Public Access): the buckets stay non-public and must_keep requesters
  keep access (`s3fix/gate.py`).
- `iam` (customer-managed policies): must_allow actions stay allowed and must_remove wildcards
  stay out (`iamfix/gate.py`).

Two inputs:
- `check_plan`: `terraform show -json` output. Exact, needs a plan (and so AWS read access).
- `check_source`: the HCL in the working tree. Offline and fast, for editor and agent hooks;
  only literal values can be judged, everything else is UNKNOWN.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from posturanet.configfix.hcl_attrs import ABSENT, BLOCK, Unsupported, lookup, resource_block
from posturanet.errors import StageStop
from posturanet.iamfix import gate as iam_gate
from posturanet.iamfix.doc import policy_json
from posturanet.locate.hcl_index import find_module_source, find_resource_block, is_local_source
from posturanet.models import BehaviorContract, Config, NetRule
from posturanet.models.iam import IamContract
from posturanet.models.s3 import S3Contract
from posturanet.s3fix import FLAG_NAMES
from posturanet.s3fix import gate as s3_gate
from posturanet.synth.sg_rules import Rule, parse_security_group
from posturanet.validate.invariants import allow_holds, deny_holds
from posturanet.validate.plan_scope import planned_rules

GateStatus = Literal["PASS", "BLOCK", "UNKNOWN"]
SG_TYPE = "aws_security_group"
IAM_TYPE = "aws_iam_policy"
AnyContract = BehaviorContract | S3Contract | IamContract


@dataclass
class Violation:
    message: str
    contract_line: int | None = None  # 1-based line in the contract file


@dataclass
class ContractResult:
    address: str
    contract_file: str
    status: GateStatus
    reasons: list[str] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    source_file: str | None = None  # repo-relative .tf file holding the changed resource
    source_line: int | None = None
    subject: str = "ingress"  # what changed: ingress, policy, public access block

    @property
    def caused_by(self) -> str | None:
        if self.source_file is None:
            return None
        where = f"{self.source_file}:{self.source_line}" if self.source_line else self.source_file
        return f"planned {self.subject} in {where}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "contract_file": self.contract_file,
            "status": self.status,
            "reasons": self.reasons,
            "violations": [v.__dict__ for v in self.violations],
            "source_file": self.source_file,
            "source_line": self.source_line,
        }


@dataclass
class GateResult:
    status: GateStatus
    results: list[ContractResult]
    mode: Literal["plan", "source"] = "plan"

    @property
    def summary(self) -> str:
        broken = [r for r in self.results if r.status == "BLOCK"]
        if broken:
            n = len(broken)
            return f"BLOCK · this change would break {n} contract{'s' * (n != 1)}"
        if self.status == "UNKNOWN":
            what = "until apply" if self.mode == "plan" else "from the source alone"
            return f"UNKNOWN · some planned changes can't be judged {what}"
        n = len(self.results)
        return f"PASS · {n} contract{'s' * (n != 1)} checked"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "mode": self.mode,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }


def _overall(results: list[ContractResult]) -> GateStatus:
    if any(r.status == "BLOCK" for r in results):
        return "BLOCK"
    if any(r.status == "UNKNOWN" for r in results):
        return "UNKNOWN"
    return "PASS"


# --- contracts of every kind


@dataclass
class _Loaded:
    contract: AnyContract
    rel: str
    text: str


def _load(path: Path, repo: Path) -> _Loaded | None:
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    models: dict[str, type[BaseModel]] = {"s3_public": S3Contract, "iam": IamContract}
    try:
        data = YAML(typ="safe").load(text)
        kind = data.get("kind", "network") if isinstance(data, dict) else "network"
        contract = models.get(kind, BehaviorContract).model_validate(data)
    except (YAMLError, ValidationError) as exc:
        raise StageStop(
            "contract",
            f"contract {path.name} is invalid",
            ["fix the YAML by hand, or delete it to regenerate a draft"],
            why=str(exc).splitlines()[0],
        ) from exc
    assert isinstance(contract, BehaviorContract | S3Contract | IamContract)
    return _Loaded(contract, path.relative_to(repo).as_posix(), text)


def _all_contracts(repo: Path, config: Config) -> list[_Loaded]:
    directory = repo / config.contracts.dir
    if not directory.is_dir():
        return []
    return [c for p in sorted(directory.glob("*.yaml")) if (c := _load(p, repo)) is not None]


def _line_of(text: str, needle: str) -> int | None:
    for i, line in enumerate(text.splitlines(), start=1):
        if needle and needle in line and not line.lstrip().startswith("#"):
            return i
    return None


def _finish(
    result: ContractResult,
    loaded: _Loaded,
    violations: list[str],
    unknowns: list[str],
    needles: list[str],
) -> ContractResult:
    for i, msg in enumerate(violations):
        needle = needles[i] if i < len(needles) else ""
        result.violations.append(Violation(msg, _line_of(loaded.text, needle)))
    result.reasons = [*(v.message for v in result.violations), *unknowns]
    result.status = "BLOCK" if result.violations else "UNKNOWN" if unknowns else "PASS"
    return result


# --- security groups (kind network)


def _rule_line(lines: list[str], section: str, rule: NetRule) -> int | None:
    """Line of `rule` inside `section:` of the contract YAML, for annotations (US-4 AC2)."""
    inside = False
    cidr = re.compile(rf"cidr:\s*['\"]?{re.escape(rule.cidr)}['\"]?\s*[,}}]")
    port = re.compile(rf"port:\s*{rule.port}\b")
    for i, line in enumerate(lines, start=1):
        if re.match(r"^[A-Za-z_]+:", line):
            inside = line.startswith(f"{section}:")
            continue
        if inside and cidr.search(line) and port.search(line):
            return i
    return None


def _judge(
    result: ContractResult, contract: BehaviorContract, rules: list[Rule], text: str
) -> ContractResult:
    lines = text.splitlines()
    draft = "" if contract.status == "approved" else " (draft contract)"
    for section, src in [
        *(("must_allow", s) for s in contract.must_allow),
        *(("needs_review", s) for s in contract.needs_review),
    ]:
        if not allow_holds(rules, src):
            who = f" ({src.owner})" if src.owner else ""
            msg = f"breaks must_allow: {src.cidr} → {src.port}/{src.proto}{who}{draft}"
            result.violations.append(Violation(msg, _rule_line(lines, section, src)))
    for d in contract.must_deny:
        if not deny_holds(rules, d):
            msg = f"breaks must_deny: {d.cidr} → {d.port}/{d.proto} is allowed{draft}"
            result.violations.append(Violation(msg, _rule_line(lines, "must_deny", d)))
    result.reasons = [v.message for v in result.violations]
    result.status = "BLOCK" if result.violations else "PASS"
    return result


def _changed(rc: dict[str, Any]) -> bool:
    actions = rc.get("change", {}).get("actions", [])
    return rc.get("mode", "managed") == "managed" and actions not in (["no-op"], ["read"])


def _deletes(rc: dict[str, Any]) -> bool:
    return "delete" in rc.get("change", {}).get("actions", [])


def check_plan(plan: dict[str, Any], repo: Path, config: Config) -> GateResult:
    contracts = _all_contracts(repo, config)
    changes = [rc for rc in plan.get("resource_changes", []) if _changed(rc)]
    by_address = {str(rc.get("address")): rc for rc in changes}
    results: list[ContractResult] = []
    for loaded in contracts:
        c = loaded.contract
        if isinstance(c, BehaviorContract):
            rc = by_address.get(c.resource)
            if rc is not None and rc.get("type") == SG_TYPE:
                results.append(_plan_sg(rc, loaded, repo, config))
        elif isinstance(c, IamContract):
            rc = by_address.get(c.resource)
            if rc is not None and rc.get("type") == IAM_TYPE:
                results.append(_plan_iam(rc, loaded, repo, config))
        else:
            res = _plan_s3(changes, loaded, repo, config)
            if res is not None:
                results.append(res)
    return GateResult(_overall(results), results, "plan")


def _located(result: ContractResult, repo: Path, config: Config, address: str) -> None:
    block = _source_block(repo, config, address)
    if isinstance(block, tuple):
        result.source_file, result.source_line = block


def _plan_sg(rc: dict[str, Any], loaded: _Loaded, repo: Path, config: Config) -> ContractResult:
    assert isinstance(loaded.contract, BehaviorContract)
    address = str(rc.get("address"))
    result = ContractResult(address, loaded.rel, "PASS")
    _located(result, repo, config, address)
    if _deletes(rc):
        result.status = "BLOCK"
        result.violations = [Violation("the plan deletes or replaces this group")]
        result.reasons = [v.message for v in result.violations]
        return result
    rules = planned_rules(rc, "after")
    if rules is None:
        result.status = "UNKNOWN"
        result.reasons = ["planned ingress is unknown until apply"]
        return result
    return _judge(result, loaded.contract, rules, loaded.text)


def _policy_of(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str) or not value.strip():
        return None
    doc = json.loads(value)
    return doc if isinstance(doc, dict) else None


def _plan_iam(rc: dict[str, Any], loaded: _Loaded, repo: Path, config: Config) -> ContractResult:
    assert isinstance(loaded.contract, IamContract)
    address = str(rc.get("address"))
    result = ContractResult(address, loaded.rel, "PASS", subject="policy")
    _located(result, repo, config, address)
    change = rc.get("change", {})
    if _deletes(rc):
        return _finish(result, loaded, ["the plan deletes or replaces this policy"], [], [])
    if (change.get("after_unknown") or {}).get("policy"):
        return _finish(result, loaded, [], ["the planned policy is unknown until apply"], [])
    try:
        doc = _policy_of((change.get("after") or {}).get("policy"))
    except json.JSONDecodeError:
        return _finish(result, loaded, [], ["the planned policy isn't valid JSON"], [])
    violations, unknowns, needles = iam_gate.judge(loaded.contract, doc or {})
    return _finish(result, loaded, violations, unknowns, needles)


def _plan_s3(
    changes: list[dict[str, Any]], loaded: _Loaded, repo: Path, config: Config
) -> ContractResult | None:
    c = loaded.contract
    assert isinstance(c, S3Contract)
    buckets = set(c.exposure)
    block = next((rc for rc in changes if rc.get("address") == c.resource), None)
    policies = [
        rc
        for rc in changes
        if rc.get("type") == s3_gate.POLICY_TYPE
        and buckets
        & {
            str((rc.get("change", {}).get(side) or {}).get("bucket"))
            for side in ("before", "after")
        }
    ]
    if block is None and not policies:
        return None
    result = ContractResult(c.resource, loaded.rel, "PASS", subject="public access block")
    violations: list[str] = []
    unknowns: list[str] = []
    needles: list[str] = []
    if block is not None:
        _located(result, repo, config, c.resource)
        if _deletes(block) and "create" not in block["change"]["actions"]:
            violations.append("the plan deletes the public access block (must_block)")
            needles.append("must_block")
        else:
            change = block.get("change", {})
            after, unknown = change.get("after") or {}, change.get("after_unknown") or {}
            flags = {f: "<unknown>" if unknown.get(f) else after.get(f) for f in FLAG_NAMES}
            v, u = s3_gate.judge_flags(c, flags)
            violations += v
            unknowns += u
            needles += ["must_block"] * len(v)
    for rc in policies:
        change = rc.get("change", {})
        bucket = str((change.get("after") or change.get("before") or {}).get("bucket"))
        if result.source_file is None:
            result.subject = "bucket policy"
            _located(result, repo, config, str(rc.get("address")))
        if (change.get("after_unknown") or {}).get("policy"):
            unknowns.append(f"the {bucket} policy is unknown until apply")
            continue
        try:
            before = _policy_of((change.get("before") or {}).get("policy"))
            after_doc = (
                None
                if _deletes(rc) and "create" not in change.get("actions", [])
                else (_policy_of((change.get("after") or {}).get("policy")))
            )
        except json.JSONDecodeError:
            unknowns.append(f"the {bucket} policy isn't valid JSON")
            continue
        v, u, n = s3_gate.judge_policy(c, bucket, after_doc, before or {})
        violations += v
        unknowns += u
        needles += n
    return _finish(result, loaded, violations, unknowns, needles)


# --- source (offline)


def check_source(repo: Path, config: Config, files: list[Path] | None = None) -> GateResult:
    """Judge every contract from the HCL. With `files`, only contracts on resources in them."""
    wanted = None if files is None else {f.resolve() for f in files}
    results: list[ContractResult] = []
    for loaded in _all_contracts(repo, config):
        c = loaded.contract
        if isinstance(c, BehaviorContract):
            res = _source_sg(loaded, repo, config, wanted)
        elif isinstance(c, IamContract):
            res = _source_iam(loaded, repo, config, wanted)
        else:
            res = _source_s3(loaded, repo, config, wanted)
        if res is not None:
            results.append(res)
    return GateResult(_overall(results), results, "source")


def _in_scope(repo: Path, file_rel: str, wanted: set[Path] | None) -> bool:
    return wanted is None or (repo / file_rel).resolve() in wanted


def _source_sg(
    loaded: _Loaded, repo: Path, config: Config, wanted: set[Path] | None
) -> ContractResult | None:
    c = loaded.contract
    assert isinstance(c, BehaviorContract)
    result = ContractResult(c.resource, loaded.rel, "PASS")
    block = _source_block(repo, config, c.resource)
    if isinstance(block, str):
        if wanted is None:
            result.status, result.reasons = "UNKNOWN", [block]
            return result
        return None
    file_rel, line = block
    result.source_file, result.source_line = file_rel, line
    if not _in_scope(repo, file_rel, wanted):
        return None
    rtype, name = _type_and_name(c.resource)
    try:
        sg = parse_security_group(repo / file_rel, line, rtype, name)
    except StageStop as exc:
        result.status, result.reasons = "UNKNOWN", [exc.reason]
        return result
    return _judge(result, c, sg.rules(), loaded.text)


def _source_iam(
    loaded: _Loaded, repo: Path, config: Config, wanted: set[Path] | None
) -> ContractResult | None:
    c = loaded.contract
    assert isinstance(c, IamContract)
    result = ContractResult(c.resource, loaded.rel, "PASS", subject="policy")
    block = _source_block(repo, config, c.resource)
    if isinstance(block, str):
        return _finish(result, loaded, [], [block], []) if wanted is None else None
    file_rel, line = block
    result.source_file, result.source_line = file_rel, line
    path = repo / file_rel
    if not _in_scope(repo, file_rel, wanted):
        return None
    try:
        doc = policy_json(path.parent, path, line)
    except Unsupported as exc:
        return _finish(result, loaded, [], [str(exc)], [])
    violations, unknowns, needles = iam_gate.judge(c, doc)
    return _finish(result, loaded, violations, unknowns, needles)


def _source_s3(
    loaded: _Loaded, repo: Path, config: Config, wanted: set[Path] | None
) -> ContractResult | None:
    c = loaded.contract
    assert isinstance(c, S3Contract)
    result = ContractResult(c.resource, loaded.rel, "PASS", subject="public access block")
    violations: list[str] = []
    unknowns: list[str] = []
    needles: list[str] = []
    touched = False
    block = _source_block(repo, config, c.resource)
    if isinstance(block, str):
        unknowns.append(block)
        directory = (repo / config.terraform.root).resolve()
        touched = wanted is None
    else:
        file_rel, line = block
        result.source_file, result.source_line = file_rel, line
        touched = _in_scope(repo, file_rel, wanted)
        text = (repo / file_rel).read_text(encoding="utf-8")
        flags: dict[str, Any] = {}
        for f in FLAG_NAMES:
            try:
                value = lookup(text, line, f)
            except Unsupported as exc:
                unknowns.append(str(exc))
                value = True
            flags[f] = None if value is ABSENT or value is BLOCK else value
        v, u = s3_gate.judge_flags(c, flags)
        violations += v
        unknowns += u
        needles += ["must_block"] * len(v)
        directory = (repo / file_rel).parent
    for pfile, pline, bucket in _bucket_policies(directory):
        if bucket is not None and bucket not in c.exposure:
            continue
        prel = pfile.resolve().relative_to(repo.resolve()).as_posix()
        if not _in_scope(repo, prel, wanted):
            continue
        touched = True
        if result.source_file is None or result.status == "PASS" and not violations:
            result.source_file, result.source_line, result.subject = prel, pline, "bucket policy"
        if bucket is None:
            unknowns.append(f"can't tell which bucket the policy in {prel}:{pline} is for")
            continue
        try:
            doc = policy_json(pfile.parent, pfile, pline)
        except Unsupported as exc:
            unknowns.append(f"{bucket} policy: {exc}")
            continue
        v, u, n = s3_gate.judge_policy(c, bucket, doc, None)
        violations += v
        unknowns += u
        needles += n
    if not touched:
        return None
    return _finish(result, loaded, violations, unknowns, needles)


_POLICY_HEADER = re.compile(r'(?m)^[ \t]*resource[ \t]+"aws_s3_bucket_policy"[ \t]+"([^"]+)"')
_BUCKET_ATTR = re.compile(r"(?m)^[ \t]*bucket[ \t]*=[ \t]*(.+?)[ \t]*$")
_BUCKET_REF = re.compile(r"^aws_s3_bucket\.([A-Za-z_][A-Za-z0-9_-]*)\.(?:id|bucket)$")


def _bucket_policies(directory: Path) -> list[tuple[Path, int, str | None]]:
    """(file, line, bucket name or None) for each `aws_s3_bucket_policy` in `directory`."""
    out: list[tuple[Path, int, str | None]] = []
    for tf in sorted(directory.glob("*.tf")):
        text = tf.read_bytes().decode("utf-8").replace("\r\n", "\n")
        for m in _POLICY_HEADER.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            blk = resource_block(text, line)
            attr = _BUCKET_ATTR.search(text, blk.open, blk.end)
            out.append((tf, line, _bucket_name(directory, attr.group(1)) if attr else None))
    return out


def _bucket_name(directory: Path, expr: str) -> str | None:
    if expr.startswith('"') and expr.endswith('"') and "${" not in expr:
        return expr[1:-1]
    ref = _BUCKET_REF.match(expr)
    if ref is None:
        return None
    found = find_resource_block(directory, "aws_s3_bucket", ref.group(1))
    if found is None:
        return None
    try:
        value = lookup(found.file.read_text(encoding="utf-8"), found.line, "bucket")
    except Unsupported:
        return None
    return value if isinstance(value, str) else None


_SEGMENT = re.compile(r"module\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.")


def _type_and_name(address: str) -> tuple[str, str]:
    tail = _SEGMENT.sub("", address)
    rtype, _, name = tail.partition(".")
    return rtype, re.sub(r"\[.*\]$", "", name)


_KNOWN = (SG_TYPE, IAM_TYPE, s3_gate.POLICY_TYPE, *s3_gate.BLOCK_TYPES)


def _source_block(repo: Path, config: Config, address: str) -> tuple[str, int] | str:
    """(file, line) of the resource block for `address`, or why it can't be found."""
    directory = (repo / config.terraform.root).resolve()
    for module in _SEGMENT.findall(address):
        found = find_module_source(directory, module)
        if found is None:
            return f'module "{module}" block not found'
        source, _ = found
        if not is_local_source(source):
            return f'module "{module}" uses a remote source ({source})'
        directory = (directory / source).resolve()
    rtype, name = _type_and_name(address)
    if rtype not in _KNOWN:
        return f"PosturaNet doesn't check {rtype} changes"
    block = find_resource_block(directory, rtype, name)
    if block is None:
        return f'resource "{rtype}" "{name}" not found in this checkout'
    try:
        file_rel = block.file.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return f"{address} is defined outside the repo"
    return file_rel, block.line
