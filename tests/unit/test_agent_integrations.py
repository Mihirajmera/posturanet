"""Every coding-agent package parses, starts `posturanet mcp` and carries the same rule (FR-40)."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

AGENTS = Path(__file__).resolve().parents[2] / "integrations" / "agents"
RULES = (AGENTS / "RULES.md").read_text(encoding="utf-8")
MCP = {"command": "posturanet", "args": ["mcp"]}

RULE_FILES = [
    "agents-md/AGENTS.posturanet.md",
    "cursor/.cursor/rules/posturanet.mdc",
    "vscode-copilot/.github/instructions/posturanet.instructions.md",
    "windsurf/.windsurf/rules/posturanet.md",
    "cline/.clinerules/posturanet.md",
    "kiro/.kiro/steering/posturanet.md",
    "continue/.continue/rules/posturanet.md",
]


def _yaml(path: Path) -> Any:
    return YAML(typ="safe").load(path.read_text(encoding="utf-8"))


def _server(path: str) -> dict[str, Any]:
    file = AGENTS / path
    if file.suffix == ".toml":
        data: Any = tomllib.loads(file.read_text(encoding="utf-8"))["mcp_servers"]
    elif file.suffix == ".yaml":
        data = _yaml(file)
        if "mcpServers" in data:  # Continue: a list of servers
            (entry,) = data["mcpServers"]
            return {"command": entry["command"], "args": entry["args"]}
        entry = data["extensions"]["posturanet"]  # Goose
        return {"command": entry["cmd"], "args": entry["args"]}
    else:
        raw = json.loads(file.read_text(encoding="utf-8"))
        data = raw.get("mcpServers") or raw.get("servers") or raw.get("context_servers")
    entry = data["posturanet"]
    return {"command": entry["command"], "args": entry["args"]}


@pytest.mark.parametrize(
    "path",
    [
        "cursor/.cursor/mcp.json",
        "codex/.codex/config.toml",
        "vscode-copilot/.vscode/mcp.json",
        "gemini/.gemini/settings.json",
        "windsurf/.devin/mcp_config.json",
        "kiro/.kiro/settings/mcp.json",
        "continue/.continue/mcpServers/posturanet.yaml",
        "zed/settings.snippet.json",
        "goose/config.snippet.yaml",
    ],
)
def test_each_agent_starts_the_mcp_server(path: str) -> None:
    assert _server(path) == MCP


def test_vscode_uses_its_own_shape() -> None:
    raw = json.loads((AGENTS / "vscode-copilot/.vscode/mcp.json").read_text(encoding="utf-8"))
    assert list(raw) == ["servers"] and raw["servers"]["posturanet"]["type"] == "stdio"


@pytest.mark.parametrize("path", RULE_FILES)
def test_rule_text_matches_rules_md(path: str) -> None:
    text = (AGENTS / path).read_text(encoding="utf-8")
    front = re.match(r"---\n(.*?)\n---\n\n", text, re.S)
    if front:
        assert isinstance(_yaml_text(front.group(1)), dict)
        text = text[front.end() :]
    assert text == RULES


def _yaml_text(text: str) -> Any:
    return YAML(typ="safe").load(text)


def test_every_package_is_listed_in_the_readme() -> None:
    readme = (AGENTS / "README.md").read_text(encoding="utf-8")
    for folder in sorted(p.name for p in AGENTS.iterdir() if p.is_dir()):
        assert f"`{folder}/`" in readme, folder
