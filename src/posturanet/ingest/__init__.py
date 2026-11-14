"""Ingest stage: turn a finding file or a manual target into a `Finding` (FR-1..FR-4, FR-4a).

A finding file is ASFF (Security Hub), OCSF (Security Hub `get-findings-v2`, Prowler
`json-ocsf`, Security Lake), a Terraform scanner report (Checkov `-o json`, Trivy
`config -f json`), or Security Hub remediation plans (FR-4c); the format is detected
from the content. A file may hold many findings: when exactly one of them is a
failed finding PosturaNet can fix, that one is used; otherwise `posturanet findings` lists or
splits them.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from posturanet.errors import StageStop, UsageError
from posturanet.ingest import asff, iac, ocsf, plans
from posturanet.ingest.asff import parse_asff_file
from posturanet.ingest.manual import finding_from_resource_id
from posturanet.models import Finding, FixType

Format = Literal["asff", "ocsf", "checkov", "trivy", "plan"]


@dataclass(frozen=True)
class Entry:
    """One finding in a file: normalized, or the reason it can't be."""

    index: int
    item: dict[str, Any]
    finding: Finding | None
    reason: str | None
    control_id: str | None = None

    @property
    def fixable(self) -> bool:
        return self.finding is not None and self.finding.fix_type is not FixType.UNSUPPORTED


@dataclass(frozen=True)
class FindingsFile:
    path: Path
    format: Format
    raw_sha256: str
    entries: list[Entry]

    @property
    def fixable(self) -> list[Entry]:
        return [e for e in self.entries if e.fixable]


def issue_of(f: Finding) -> tuple[str, str, str]:
    """The same problem across scanner files, before locate: control, account, short resource id.

    `arn:aws:ec2:us-east-1:123456789012:security-group/sg-1` and `sg-1` are one resource.
    shortcut: Checkov/Trivy name a Terraform address, not an id, so they only merge with the
    others at PR time (idempotency.issue on the located address).
    """
    rid = f.resource.id
    parts = rid.split(":")
    account = parts[4] if rid.startswith("arn:") and len(parts) > 5 else f.resource.account or ""
    return f.control_id, account, parts[-1].rsplit("/", 1)[-1]


def read_findings(path: Path) -> FindingsFile:
    if not path.is_file():
        raise UsageError(f"finding file not found: {path}")
    raw = path.read_bytes()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UsageError(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    sha = hashlib.sha256(raw).hexdigest()
    fmt, items = _items(doc)
    entries = [_entry(i, item, fmt, sha) for i, item in enumerate(items)]
    return FindingsFile(path=path, format=fmt, raw_sha256=sha, entries=entries)


def parse_item(item: dict[str, Any], fmt: Format, *, raw_sha256: str) -> Finding:
    if fmt == "ocsf":
        return ocsf.parse_ocsf_item(item, raw_sha256=raw_sha256)
    if fmt == "checkov":
        return iac.parse_checkov_item(item, raw_sha256=raw_sha256)
    if fmt == "trivy":
        return iac.parse_trivy_item(item, raw_sha256=raw_sha256)
    if fmt == "plan":
        return plans.parse_plan_item(item, raw_sha256=raw_sha256)
    return asff.parse_asff_item(item, raw_sha256=raw_sha256)


def document_for(item: dict[str, Any], fmt: Format) -> Any:
    """A file holding just this finding, in its scanner's own format."""
    if fmt == "checkov":
        return iac.checkov_document(item)
    if fmt == "trivy":
        return iac.trivy_document(item)
    if fmt == "ocsf":
        return item
    if fmt == "plan":
        return plans.plan_document(item)
    return {"Findings": [item]}


def ingest(target: str) -> Finding:
    """`target` is a finding file (ASFF, OCSF, Checkov or Trivy JSON), or a resource id
    such as `sg-0a91f3c2`."""
    path = Path(target)
    if not (path.suffix.lower() == ".json" or path.is_file()):
        return finding_from_resource_id(target)
    found = read_findings(path)
    if len(found.entries) == 1:
        return parse_item(found.entries[0].item, found.format, raw_sha256=found.raw_sha256)
    if not found.entries:
        raise UsageError(f"{path} holds no failed findings: nothing to fix")
    fixable = found.fixable
    if len(fixable) == 1 and fixable[0].finding is not None:
        return fixable[0].finding
    raise UsageError(
        f"{path} holds {len(found.entries)} findings, {len(fixable)} of them failed findings "
        f"PosturaNet can fix; see them with `posturanet findings list {path}` and write one "
        f"file each with `posturanet findings split {path} --out findings/`"
    )


def _items(doc: Any) -> tuple[Format, list[dict[str, Any]]]:
    if plans.looks_like_plans(doc):
        return "plan", plans.plan_items(doc)
    doc = ocsf.unwrap(doc)  # get-findings-v2 output and EventBridge events hold OCSF
    if isinstance(doc, dict) and "Findings" in doc:
        return "asff", asff.findings_in(doc)
    if iac.looks_like_checkov(doc):
        return "checkov", iac.checkov_items(doc)
    if iac.looks_like_trivy(doc):
        return "trivy", iac.trivy_items(doc)
    first = doc[0] if isinstance(doc, list) and doc else doc
    if isinstance(first, dict) and ocsf.looks_like_ocsf(first):
        return "ocsf", ocsf.findings_in(doc)
    return "asff", asff.findings_in(doc)


def _entry(index: int, item: dict[str, Any], fmt: Format, sha: str) -> Entry:
    try:
        finding = parse_item(item, fmt, raw_sha256=sha)
        return Entry(index, item, finding, None, finding.control_id)
    except StageStop as exc:
        control = None
        if fmt == "ocsf":
            with contextlib.suppress(StageStop):
                control = ocsf.control_id_of(item)
        return Entry(index, item, None, exc.reason, control)


__all__ = [
    "Entry",
    "FindingsFile",
    "finding_from_resource_id",
    "ingest",
    "parse_asff_file",
    "document_for",
    "parse_item",
    "read_findings",
]
