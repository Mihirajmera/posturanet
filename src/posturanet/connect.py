"""`posturanet connect`: how to feed a scanner's findings in, and wire up coding agents and CI.

Agent and CI files come from `integrations/` (packaged into the wheel as `_integrations/`).
`--write` copies them into the user's repo and never overwrites a file that already exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Target:
    name: str
    kind: str  # scanner | agent | ci
    summary: str
    steps: tuple[str, ...]  # commands or instructions, in order
    files: tuple[tuple[str, str], ...] = field(default=())  # (source in integrations/, dest)


def _plan(f: str) -> tuple[str, str]:
    return f"posturanet findings list {f}", f"posturanet findings split {f} --out findings/"


_MCP = 'pip install "posturanet[mcp]"'


def _agent(name: str, folder: str, *paths: str, alt: str = "") -> Target:
    files = tuple((f"agents/{folder}/{p}", p) for p in paths)
    steps: tuple[str, ...] = (_MCP, f"posturanet connect {name} --write --repo .")
    steps += (f"or: {alt}",) if alt else ()
    return Target(name, "agent", "MCP server + rule: check_change before merging", steps, files)


TARGETS: tuple[Target, ...] = (
    Target("securityhub", "scanner", "AWS Security Hub findings (ASFF or OCSF) and remediation plans", (  # noqa: E501 (copyable example)
        "aws securityhub get-findings --filters "
        "'{\"ComplianceStatus\":[{\"Value\":\"FAILED\",\"Comparison\":\"EQUALS\"}]}' > findings.json",  # noqa: E501 (copyable example)
        *_plan("findings.json"),
        "plans: posturanet findings pull-plans --out plans.json",
    )),
    Target("prowler", "scanner", "Prowler OCSF (or ASFF) output", (
        "prowler aws --output-formats json-ocsf --output-directory prowler-out/",
        *_plan("prowler-out/<file>.ocsf.json"),
    )),
    Target("checkov", "scanner", "Checkov JSON on your Terraform", (
        "checkov -d infra/ -o json > checkov.json",
        *_plan("checkov.json"),
        "PosturaNet maps the Terraform address to the deployed resource through state",
    )),
    Target("trivy", "scanner", "Trivy misconfiguration JSON on your Terraform", (
        "trivy config -f json -o trivy.json infra/",
        *_plan("trivy.json"),
    )),
    Target("wiz", "scanner", "not supported yet", (
        "export Wiz issues to Security Hub, or open an issue on GitHub to ask for direct support",
    )),
    Target("claude-code", "agent", "plugin: skill, MCP server, a hook after every .tf edit", (
        "in Claude Code: /plugin marketplace add Mihirajmera/posturanet",
        "then: /plugin install posturanet@posturanet",
    )),
    _agent("cursor", "cursor", ".cursor/mcp.json", ".cursor/rules/posturanet.mdc"),
    _agent("codex", "codex", ".codex/config.toml", alt="codex mcp add posturanet -- posturanet mcp"),  # noqa: E501 (copyable example)
    _agent(
        "copilot", "vscode-copilot", ".vscode/mcp.json",
        ".github/instructions/posturanet.instructions.md",
    ),
    _agent("gemini", "gemini", ".gemini/settings.json"),
    _agent("windsurf", "windsurf", ".devin/mcp_config.json", ".windsurf/rules/posturanet.md"),
    _agent("cline", "cline", ".clinerules/posturanet.md", alt="cline mcp add posturanet --yes -- posturanet mcp"),  # noqa: E501 (copyable example)
    _agent("kiro", "kiro", ".kiro/settings/mcp.json", ".kiro/steering/posturanet.md"),
    _agent(
        "continue", "continue", ".continue/mcpServers/posturanet.yaml",
        ".continue/rules/posturanet.md",
    ),
    Target("zed", "agent", "MCP server in Zed's settings", (
        _MCP,
        'add to Zed settings: "context_servers": {"posturanet": {"command": "posturanet", "args": ["mcp"]}}',  # noqa: E501 (copyable example)
    )),
    Target("goose", "agent", "MCP extension", (_MCP, 'goose session --with-extension "posturanet mcp"')),  # noqa: E501 (copyable example)
    Target("other", "agent", "any MCP client, and agents that read AGENTS.md", (
        _MCP,
        "MCP server command: posturanet mcp (tools: explain_finding, propose_fix, check_change)",
        "posturanet connect other --write --repo .   appends the rule to AGENTS.md",
    ), (("agents/agents-md/AGENTS.posturanet.md", "AGENTS.md"),)),
    Target("github", "ci", "a PosturaNet contract check on every pull request", (
        "posturanet connect github --write --repo .",
        "or in any CI: posturanet contract check --plan plan.json   (exit 5 on BLOCK)",
    ), (("github/posturanet-check.yml", ".github/workflows/posturanet-check.yml"),)),
)  # fmt: skip
BY_NAME = {t.name: t for t in TARGETS}


def integrations_dir() -> Path:
    here = Path(__file__).resolve().parent
    packaged = here / "_integrations"
    return packaged if packaged.is_dir() else here.parents[1] / "integrations"


def write(target: Target, repo: Path) -> list[tuple[str, str]]:
    """Copy the target's files into `repo`. Returns (dest, outcome) per file; never overwrites.

    AGENTS.md is the one file appended to, because it usually exists already.
    """
    src_root = integrations_dir()
    results = []
    for src, dest in target.files:
        text = (src_root / src).read_text(encoding="utf-8")
        out = repo / dest
        if dest == "AGENTS.md" and out.exists():
            current = out.read_text(encoding="utf-8")
            if "posturanet" in current.lower():
                results.append((dest, "already mentions PosturaNet, left as is"))
                continue
            out.write_text(current.rstrip("\n") + "\n\n" + text, encoding="utf-8")
            results.append((dest, "appended"))
        elif out.exists():
            results.append((dest, "exists, left as is"))
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            results.append((dest, "written"))
    return results
