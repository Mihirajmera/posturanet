"""AI agent hooks: check an agent's change before or right after it makes it.

Claude Code calls `posturanet hook claude-code`:
- as a PostToolUse hook on Edit/Write. The check is `gate.check_source` (offline, no plan, no
  AWS), limited to the edited file: a `.tf` file or a CloudFormation/SAM template; other YAML
  and JSON files are left alone.
- as a PreToolUse hook on Bash (FR-55). A command that destroys infrastructure or data
  (`terraform destroy`, `apply -auto-approve`, `aws rds delete-db-instance`, ...) is sent back
  to the user to approve instead of running on the agent's say-so.

The event JSON is untrusted data: only `hook_event_name`, `tool_name`, `tool_input.file_path`
and `tool_input.command` are read from it.
"""

from __future__ import annotations

import json
from pathlib import Path

from posturanet.cfn import template as cfn_template
from posturanet.destructive import destructive_command
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


def _event(event_text: str) -> dict[str, object]:
    try:
        event = json.loads(event_text)
    except json.JSONDecodeError:
        return {}
    return event if isinstance(event, dict) else {}


def _edited_file(event: dict[str, object]) -> Path | None:
    tool_input = event.get("tool_input")
    path = tool_input.get("file_path") if isinstance(tool_input, dict) else None
    if not isinstance(path, str):
        return None
    file = Path(path)
    if file.suffix == ".tf" or cfn_template.maybe_template(file) is not None:
        return file
    return None  # any other file, including YAML/JSON that isn't a CloudFormation template


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


def _pre_bash(event: dict[str, object]) -> str:
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    what = destructive_command(command) if isinstance(command, str) else None
    if what is None:
        return ""
    reason = (
        f"PosturaNet: this command {what}. A person should approve it after reading the plan. "
        "Prefer a plan the user reviews (terraform plan -out, then terraform apply of that plan)."
    )
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }
    return json.dumps(out) + "\n"


def claude_code(event_text: str, repo: Path) -> str:
    """Hook stdout. Empty when there is nothing to say."""
    event = _event(event_text)
    if event.get("hook_event_name") == "PreToolUse":
        return _pre_bash(event) if event.get("tool_name") == "Bash" else ""
    file = _edited_file(event)
    if file is None or not file.is_file():
        return ""
    result = check_edit(file, repo)
    if isinstance(result, str):
        return _context(result) + "\n"
    if not result.results:
        return ""
    report = render_gate(result, ascii_mode=True, framed=False)
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
        then = (
            "Run `posturanet contract check --plan plan.json` before relying on it."
            if file.suffix == ".tf"
            else "Keep contracted properties as literal values the template parses, or ask the "
            "user to review the change against the contract."
        )
        return (
            _context(
                report + "\nPosturaNet could not judge this edit from the source alone. " + then
            )
            + "\n"
        )
    return ""
