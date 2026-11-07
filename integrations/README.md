# Add PosturaNet to your pipeline

PosturaNet's contract check runs where you already work. It answers one question about a
security group change, whoever wrote it, a person or an AI agent: **does this still allow every
source that really uses the group, and does it keep denied networks closed?**

It needs a behavior contract for the group (`posturanet contract build <sg-id>`, then merge the
PR that adds `posturanet/contracts/<address>.yaml`). Groups without a contract are not checked.

| Result | Meaning | Exit code | Check run |
|---|---|---|---|
| `PASS` | every contract holds | 0 | `success` |
| `BLOCK` | a `must_allow` source would be cut off, a `must_deny` network opened, or the group deleted | 5 | `failure` |
| `UNKNOWN` | PosturaNet can't judge it (computed values, `dynamic` blocks, remote modules) | 3 | `neutral` |

UNKNOWN is never shown as green. Z3 checks cover ingress CIDR, port and protocol only; security
group references, prefix lists and egress are outside the model.

## Two ways to check

| | `--plan` | `--source` |
|---|---|---|
| Input | `terraform show -json` output | the `.tf` files in the checkout |
| Needs | terraform, read-only AWS credentials | nothing (offline, under a second) |
| Judges | everything the plan knows | literal inline `ingress` blocks; anything else is UNKNOWN |
| Use for | the PR check | editor and AI agent hooks, quick local checks |

```bash
terraform plan -lock=false -out tfplan && terraform show -json tfplan > plan.json
posturanet contract check --plan plan.json
posturanet contract check --source --file modules/bastion/main.tf
```

## 1. GitHub pull requests
Copy [`github/posturanet-check.yml`](github/posturanet-check.yml) to `.github/workflows/`.
Every PR touching `*.tf` or a contract gets a **PosturaNet contract** check run. On BLOCK the
check fails and annotates the exact contract line and the resource block:

```text
✗ module.bastion.aws_security_group.this
  breaks must_allow: 203.0.113.7/32 → 22/tcp (partner-sftp)
  caused by: planned ingress in modules/bastion/main.tf:12
  → keep the rule, or update the contract in the same PR with owner approval
```

The job needs `checks: write`. Make it a required status check in branch protection to stop a
merge on BLOCK. Set `fail-on-unknown: "false"` if UNKNOWN should not fail the job.

## 2. Any other CI
After your existing `terraform plan` step:
```bash
terraform show -json tfplan > plan.json
posturanet contract check --plan plan.json        # exit 5 fails the build on BLOCK
```
To publish a GitHub check run from another CI, add `--github-check --sha <commit>` and set
`GITHUB_TOKEN` (with `checks: write`) and `GITHUB_REPOSITORY`.

## 3. Claude Code
Install the plugin (skill, MCP server and hook) from this repo's marketplace, after
`pip install "posturanet[mcp]"`:
```text
/plugin marketplace add Mihirajmera/posturanet
/plugin install posturanet@posturanet
```
The plugin lives in [`../plugin`](../plugin). Or copy [`claude-code/settings.json`](claude-code/settings.json) into `.claude/settings.json` and
[`claude-code/.mcp.json`](claude-code/.mcp.json) into the repo root.

After every edit to a `.tf` file, the hook runs `posturanet hook claude-code`. On BLOCK, Claude
gets the reason and fixes its own change before going on. On UNKNOWN it is told to check with a
plan. The hook only reads the file path from the event and never writes anything.

## 4. Cursor, Codex, Copilot, Gemini, Windsurf, Cline, Kiro, Continue, Zed, Goose
[`agents/`](agents/README.md) has a ready-made folder per agent: its MCP server entry and a rule
that tells it to call `check_change` with the edited files and stop on BLOCK. Copy the folder
into your repo root. Any other MCP client works the same way: run `posturanet mcp` and call
`check_change`.

## What PosturaNet never does here
No AWS writes (the role is read-only), no `terraform apply`, no merge, no state lock
(`-lock=false`). Nothing leaves your runner except the check run sent to your own GitHub.
