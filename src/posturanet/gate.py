"""Check a change against the behavior contracts in the repo (US-4, US-7, MCP check_change).

Read-only. A change that would block a contract source or reopen a denied network is BLOCK.
A change whose rules can't be known (computed at apply, non-literal HCL, remote module) is
UNKNOWN, never PASS.

Two inputs:
- `check_plan`: `terraform show -json` output. Exact, needs a plan (and so AWS read access).
- `check_source`: the HCL in the working tree. Offline and fast, for editor and agent hooks;
  only literal inline `ingress` blocks can be judged, everything else is UNKNOWN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from posturanet.contracts import contract_path, load_contract
from posturanet.errors import StageStop
from posturanet.locate.hcl_index import find_module_source, find_resource_block, is_local_source
from posturanet.models import BehaviorContract, Config, NetRule
from posturanet.synth.sg_rules import Rule, parse_security_group
from posturanet.validate.invariants import allow_holds, deny_holds
from posturanet.validate.plan_scope import planned_rules

GateStatus = Literal["PASS", "BLOCK", "UNKNOWN"]
SG_TYPE = "aws_security_group"


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
    source_file: str | None = None  # repo-relative .tf file holding the resource
    source_line: int | None = None

    @property
    def caused_by(self) -> str | None:
        if self.source_file is None:
            return None
        where = f"{self.source_file}:{self.source_line}" if self.source_line else self.source_file
        return f"planned ingress in {where}"

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
            return f"UNKNOWN · some planned rules can't be known {what}"
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


def _contract(repo: Path, config: Config, address: str) -> tuple[BehaviorContract, str, str] | None:
    path = contract_path(repo, config.contracts.dir, address)
    contract = load_contract(path)
    if contract is None:
        return None
    return contract, path.relative_to(repo).as_posix(), path.read_text(encoding="utf-8")


def check_plan(plan: dict[str, Any], repo: Path, config: Config) -> GateResult:
    results: list[ContractResult] = []
    for rc in plan.get("resource_changes", []):
        if rc.get("type") != SG_TYPE or rc.get("mode", "managed") != "managed":
            continue
        actions = rc.get("change", {}).get("actions", [])
        if actions in (["no-op"], ["read"]):
            continue
        address = str(rc.get("address"))
        found = _contract(repo, config, address)
        if found is None:
            continue
        contract, rel, text = found
        result = ContractResult(address, rel, "PASS")
        block = _source_block(repo, config, address)
        if isinstance(block, tuple):
            result.source_file, result.source_line = block
        if "delete" in actions:
            result.status = "BLOCK"
            result.violations = [Violation("the plan deletes or replaces this group")]
            result.reasons = [v.message for v in result.violations]
            results.append(result)
            continue
        rules = planned_rules(rc, "after")
        if rules is None:
            result.status = "UNKNOWN"
            result.reasons = ["planned ingress is unknown until apply"]
            results.append(result)
            continue
        results.append(_judge(result, contract, rules, text))
    return GateResult(_overall(results), results, "plan")


def check_source(repo: Path, config: Config, files: list[Path] | None = None) -> GateResult:
    """Judge every contracted group from its HCL. With `files`, only groups defined in them."""
    wanted = None if files is None else {f.resolve() for f in files}
    contracts_dir = repo / config.contracts.dir
    results: list[ContractResult] = []
    for path in sorted(contracts_dir.glob("*.yaml")) if contracts_dir.is_dir() else []:
        contract = load_contract(path)
        if contract is None:
            continue
        address = contract.resource
        rel = path.relative_to(repo).as_posix()
        text = path.read_text(encoding="utf-8")
        result = ContractResult(address, rel, "PASS")
        block = _source_block(repo, config, address)
        if isinstance(block, str):
            if wanted is None:
                result.status, result.reasons = "UNKNOWN", [block]
                results.append(result)
            continue
        file_rel, line = block
        result.source_file, result.source_line = file_rel, line
        if wanted is not None and (repo / file_rel).resolve() not in wanted:
            continue
        rtype, name = _type_and_name(address)
        try:
            sg = parse_security_group(repo / file_rel, line, rtype, name)
        except StageStop as exc:
            result.status, result.reasons = "UNKNOWN", [exc.reason]
            results.append(result)
            continue
        results.append(_judge(result, contract, sg.rules(), text))
    return GateResult(_overall(results), results, "source")


_SEGMENT = re.compile(r"module\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.")


def _type_and_name(address: str) -> tuple[str, str]:
    tail = _SEGMENT.sub("", address)
    rtype, _, name = tail.partition(".")
    return rtype, re.sub(r"\[.*\]$", "", name)


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
    if rtype != SG_TYPE:
        return f"{rtype} is not a security group"
    block = find_resource_block(directory, rtype, name)
    if block is None:
        return f'resource "{rtype}" "{name}" not found in this checkout'
    try:
        file_rel = block.file.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return f"{address} is defined outside the repo"
    return file_rel, block.line
