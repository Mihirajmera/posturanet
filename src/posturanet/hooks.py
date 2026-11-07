"""AI agent hooks: check an edit against the contracts right after the agent makes it.

Claude Code calls `posturanet hook claude-code` as a PostToolUse hook on Edit/Write. The check
is `gate.check_source` (offline, no plan, no AWS), limited to the edited file. The event JSON is
untrusted data: only `tool_input.file_path` is read from it.
"""

from __future__ import annotations

import json
from pathlib import Path

from posturanet.errors import PosturaNetError
from posturanet.gate import GateResult, check_source
from posturanet.models.config import load_config
from posturanet.output.console import render_gate

CONFIG_FILE = ".posturanet.yml"


def find_repo(file: Path, fallback: Path) -> Path:
    """Nearest directory above `file` holding `.posturanet.yml`, else `fallback`."""
    for parent in file.resolve().parents:
        if (parent / CONFIG_FILE).is_file():
            return parent
    return fallback


def _edited_file(event_text: str) -> Path | None:
    try:
        event = json.loads(event_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(event, dict):
        return None
    tool_input = event.get("tool_input")
    path = tool_input.get("file_path") if isinstance(tool_input, dict) else None
    if not isinstance(path, str) or not path.endswith(".tf"):
        return None
    return Path(path)


def _context(text: str) -> str:
    return json.dumps(
        {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": text}}
    )


def check_edit(file: Path, repo: Path) -> GateResult | str:
    root = find_repo(file, repo)
    try:
        config, _ = load_config(root)
        return check_source(root, config, [file])
    except PosturaNetError as exc:
        return f"PosturaNet could not check {file.name}: {exc}"


def claude_code(event_text: str, repo: Path) -> str:
    """Hook stdout. Empty when there is nothing to say."""
    file = _edited_file(event_text)
    if file is None or not file.is_file():
        return ""
    result = check_edit(file, repo)
    if isinstance(result, str):
        return _context(result) + "\n"
    if not result.results:
        return ""
    report = render_gate(result, ascii_mode=True)
    if result.status == "BLOCK":
        reason = (
            report
            + "\nThis edit removes access that real usage depends on, or reopens something the "
            "contract keeps closed. Revert or adjust the change so the contract holds, or ask the "
            "user to update the contract with the owner's approval. Do not edit the contract "
            "yourself."
        )
        return json.dumps({"decision": "block", "reason": reason}) + "\n"
    if result.status == "UNKNOWN":
        return (
            _context(
                report + "\nPosturaNet could not judge this edit from the source alone. Run "
                "`posturanet contract check --plan plan.json` before relying on it."
            )
            + "\n"
        )
    return ""
