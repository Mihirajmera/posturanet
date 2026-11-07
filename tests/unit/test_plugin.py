"""The Claude Code plugin and marketplace stay installable (FR-41)."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"


def _load(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_marketplace_points_at_the_plugin() -> None:
    market = _load(MARKETPLACE)
    assert market["name"] == "posturanet"
    assert isinstance(market["owner"], dict) and market["owner"]["name"]
    plugins = market["plugins"]
    assert isinstance(plugins, list) and len(plugins) == 1
    entry = plugins[0]
    source = entry["source"]
    assert source.startswith("./") and ".." not in source
    manifest = _load(ROOT / source / ".claude-plugin" / "plugin.json")
    # The install id is <entry name>@<marketplace>; a mismatch makes install fail.
    assert entry["name"] == manifest["name"] == "posturanet"


def test_plugin_wires_mcp_server_hook_and_skill() -> None:
    plugin = ROOT / "plugin"
    manifest = _load(plugin / ".claude-plugin" / "plugin.json")
    assert manifest["mcpServers"] == {"posturanet": {"command": "posturanet", "args": ["mcp"]}}
    hooks = manifest["hooks"]
    assert isinstance(hooks, dict) and "hooks" not in hooks  # inline form has no wrapper
    commands = [h["command"] for group in hooks["PostToolUse"] for h in group["hooks"]]
    assert commands == ["posturanet hook claude-code"]
    assert sorted(p.name for p in (plugin / ".claude-plugin").iterdir()) == ["plugin.json"]

    skill = (plugin / "skills" / "posturanet" / "SKILL.md").read_text(encoding="utf-8")
    front = re.match(r"---\nname: posturanet\ndescription: (.+?)\n---\n", skill, re.S)
    assert front, "SKILL.md needs name and description frontmatter"
    for control in ("EC2.19", "S3.8", "IAM.21"):
        assert control in front.group(1)


def test_plugin_says_posturanet() -> None:
    texts = [p.read_text(encoding="utf-8") for p in (ROOT / "plugin").rglob("*") if p.is_file()]
    texts.append(MARKETPLACE.read_text(encoding="utf-8"))
    for text in texts:
        assert not re.search(r"\bPostura\b(?!Net)", text)
