# Add PosturaNet to your pipeline

PosturaNet's contract check runs where you already work. It answers one question about a
change, whoever wrote it, a person or an AI agent: **does everything that really uses this
resource keep working, and does what the contract keeps closed stay closed?**

| Contract kind | Resources | BLOCK when |
|---|---|---|
| `network` | `aws_security_group` | a `must_allow` source is cut off, a `must_deny` network opened, or the group deleted |
| `s3_public` | `aws_s3_bucket_public_access_block`, `aws_s3_account_public_access_block`, `aws_s3_bucket_policy` | a Block Public Access setting is off or the block deleted, a policy allows `Principal *`, a policy denies a `must_keep` requester, or (with a plan) a cross-account requester loses its grant |
| `iam` | `aws_iam_policy` | a `must_allow` action is no longer allowed or is denied, a `must_remove` wildcard comes back, or the policy is deleted |

It needs a contract for the resource: `posturanet contract build <sg-id>` for a group, or the
draft that `posturanet fix` writes for an S3 or IAM fix; merge the PR that adds
`posturanet/contracts/<address>.yaml`. Resources without a contract are not checked.

| Result | Meaning | Exit code | Check run |
|---|---|---|---|
| `PASS` | every contract holds | 0 | `success` |
| `BLOCK` | a `must_allow` source would be cut off, a `must_deny` network opened, or the group deleted | 5 | `failure` |
| `UNKNOWN` | PosturaNet can't judge it (computed values, `dynamic` blocks, remote modules) | 3 | `neutral` |

UNKNOWN is never shown as green. Z3 checks cover ingress CIDR, port and protocol only; security
group references, prefix lists and egress are outside the model. For S3 and IAM, policy
conditions aren't evaluated (a conditional grant or Deny is UNKNOWN, except a TLS-only Deny), and
IAM resources are outside the model. Without a plan, a cross-account requester with no grant in
the policy is UNKNOWN: it may get in another way.

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
  → keep the access, or update the contract in the same PR with owner approval
```

On BLOCK or UNKNOWN the Action also leaves one comment on the PR with the same result, and edits
that comment on later pushes (it turns green when the change is fixed). A PR that is green from
the start gets no comment. Set `comment: "false"` to turn it off.

The job needs `checks: write` and, for the comment, `pull-requests: write`. A fork PR's token
can't comment; the check still runs. Make it a required status check in branch protection to stop a
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
