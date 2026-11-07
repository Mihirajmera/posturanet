# PosturaNet for every coding agent

Each folder here holds the files one agent needs, at the paths they go in **your** Terraform
repo: an MCP server entry (`posturanet mcp`, tools `explain_finding`, `propose_fix`,
`check_change`) and a rule that tells the agent to check security group, S3 and IAM edits and stop on BLOCK.
Every rule file has the same text as [RULES.md](RULES.md).

First, on the machine the agent runs on:
```bash
pip install "posturanet[mcp]"
```
Then copy the agent's folder into your repo root (from a clone of this repo):
```bash
cp -r integrations/agents/<agent>/. /path/to/your-terraform-repo/
```

| Agent | Folder | What it adds | One-line alternative |
|---|---|---|---|
| Claude Code | (plugin) | skill, MCP server, post-edit hook | `/plugin marketplace add Mihirajmera/posturanet` then `/plugin install posturanet@posturanet` |
| Cursor | `cursor/` | `.cursor/mcp.json`, `.cursor/rules/posturanet.mdc` | |
| OpenAI Codex | `codex/` | `.codex/config.toml` (trusted projects only) | `codex mcp add posturanet -- posturanet mcp` |
| VS Code + Copilot | `vscode-copilot/` | `.vscode/mcp.json`, `.github/instructions/posturanet.instructions.md` | `code --add-mcp '{"name":"posturanet","type":"stdio","command":"posturanet","args":["mcp"]}'` |
| Gemini CLI | `gemini/` | `.gemini/settings.json` | |
| Windsurf / Devin Local | `windsurf/` | `.devin/mcp_config.json`, `.windsurf/rules/posturanet.md` | |
| Cline | `cline/` | `.clinerules/posturanet.md` | `cline mcp add posturanet --yes -- posturanet mcp` (Cline keeps MCP servers per user) |
| Kiro | `kiro/` | `.kiro/settings/mcp.json`, `.kiro/steering/posturanet.md` | |
| Continue | `continue/` | `.continue/mcpServers/posturanet.yaml`, `.continue/rules/posturanet.md` | |
| Zed | `zed/` | merge `settings.snippet.json` into Zed's settings | rules: see below |
| Goose | `goose/` | merge `config.snippet.yaml` into `~/.config/goose/config.yaml` | `goose session --with-extension "posturanet mcp"` |
| Anything else | `agents-md/` | append to your `AGENTS.md` | any MCP client: server command `posturanet mcp` |

**Rules for agents that read `AGENTS.md`** (Codex, Copilot, Cline, Zed, Kiro, Windsurf/Devin,
Gemini via `GEMINI.md`): append [`agents-md/AGENTS.posturanet.md`](agents-md/AGENTS.posturanet.md)
to the file:
```bash
cat integrations/agents/agents-md/AGENTS.posturanet.md >> /path/to/your-terraform-repo/AGENTS.md
```
Zed reads only the first of `.rules`, `.cursorrules`, …, `AGENTS.md` it finds, so put the text in
whichever of those your repo already has.

## What runs automatically

Only the Claude Code plugin runs the check by itself after every `.tf` edit (a hook). Every other
agent gets the check through the rule: the agent calls `check_change` after editing, and stops on
BLOCK. For a hard stop no agent can skip, add the PR check in [`../github/`](../github/) or
`posturanet contract check --plan plan.json` in CI.

## What PosturaNet never does here
The MCP tools are read-only: no AWS writes, no `terraform apply`, no file writes, no PRs. Only
`posturanet fix --open-pr`, run by a person or after their explicit OK, writes to GitHub.
