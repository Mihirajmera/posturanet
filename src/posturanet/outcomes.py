"""Every failed finding ends in an outcome: a fix, a runbook, an accepted exception, or none yet.

Coverage is failed findings with an outcome ÷ all failed findings (reports/coverage-roadmap.md).
"""

from __future__ import annotations

import json
from datetime import date
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Literal

from pydantic import ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from posturanet.errors import UsageError
from posturanet.ingest import Entry
from posturanet.models.exceptions import AcceptedRisk, ExceptionsFile

Kind = Literal["fix", "runbook", "exception", "passed", "none"]
# shortcut: every ingest parser ends a non-failed reason with this; a flag on Entry if that changes
_PASSED = "there is nothing to fix"
EXCEPTIONS_FILE = Path(".posturanet/exceptions.yaml")


@cache
def _runbooks() -> dict[str, tuple[str, ...]]:
    raw = json.loads(resources.files("posturanet").joinpath("runbooks.json").read_text("utf-8"))
    return {k: tuple(v) for k, v in raw.items() if not k.startswith("_")}


def runbook_for(control: str | None) -> tuple[str, ...] | None:
    return _runbooks().get(control or "")


def load_exceptions(path: Path) -> list[AcceptedRisk]:
    """The accepted risks in `path`; none when the default file doesn't exist."""
    if not path.is_file():
        if path != EXCEPTIONS_FILE:
            raise UsageError(f"exceptions file not found: {path}")
        return []
    try:
        doc = YAML(typ="safe").load(path.read_text(encoding="utf-8")) or {}
        return ExceptionsFile.model_validate(doc).exceptions
    except (YAMLError, ValidationError) as exc:
        raise UsageError(f"{path}: not a valid exceptions file: {exc}") from exc


def outcome(entry: Entry, accepted: list[AcceptedRisk], today: date) -> tuple[Kind, str | None]:
    """The entry's outcome and a short note. An accepted risk wins over a fix until it expires."""
    if entry.reason and entry.reason.endswith(_PASSED):
        return "passed", None
    control = entry.control_id
    resource = entry.finding.resource.id if entry.finding else None
    expired = None
    for risk in accepted:
        if risk.matches(control, resource):
            if risk.expires >= today:
                return "exception", f"accepted by {risk.owner} until {risk.expires}"
            expired = f"exception expired {risk.expires}"
    if entry.fixable:
        return "fix", expired
    if runbook_for(control):
        return "runbook", expired or f"posturanet fixes show {control}"
    return "none", expired
