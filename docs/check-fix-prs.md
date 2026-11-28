# Check every fix PR, whoever wrote it

Wiz, Prowler, Gomboc, Orca, Security Hub remediation plans and coding agents (Claude Code,
Cursor, Copilot, Codex) can all open infrastructure fix PRs now. PosturaNet can be the one check
all of them pass before merge. It doesn't matter who wrote the change: the check reads the
change, not the author.

What it blocks:

- **A broken contract.** The change removes access that real usage depends on, or reopens
  something a contract keeps closed (security groups, S3 public access, IAM policies). See
  `posturanet contract build`.
- **Deleted data** (with a plan). The change deletes or replaces a database, bucket, volume,
  file system, KMS key, VPC, backup vault or log group, or turns off deletion protection, the
  final snapshot or backups (PRD FR-55). A person approves a deletion by adding the address to
  `contracts.allow_destroy` in `.posturanet.yml`, in the same PR.

## Set it up (10 minutes)

1. Copy [`integrations/github/posturanet-check.yml`](../integrations/github/posturanet-check.yml)
   to `.github/workflows/` in the infrastructure repo.
   - Use **Option A (plan)** where you can: it's the only mode that sees deletions.
   - For CloudFormation, CDK or Pulumi, widen `paths:` to your templates or program files, for
     example `"**/*.yaml"`, `"cdk/**"` or `"Pulumi.yaml"`.
2. **Make the check required**: Settings → Branches (or Rulesets) → require status checks →
   add **PosturaNet contract**. A BLOCK then stops the merge button for everyone, bots included.
3. Optional: in `CODEOWNERS`, give `posturanet/contracts/` and `.posturanet.yml` to the platform
   or security team. A fix bot then can't approve its own change by editing a contract or the
   `allow_destroy` list.

## Bots that open PRs from forks or apps

- **GitHub Apps (Wiz, Prowler, Gomboc and others)** open PRs from a branch in your repo, so
  the workflow runs normally.
- **Fork PRs** get a read-only token: the check run still reports, but the comment may be
  refused (a warning, never a changed result). Plan mode needs the AWS role, so use
  `source-only: "true"` for forks and keep the role off them.
- **Coding agents in the editor** get the same answers earlier: the Claude Code plugin checks
  each edit and asks before destroy commands, and other agents call the MCP tool
  `check_change` (see [`integrations/`](../integrations/README.md)).

## What it can't see

- Source mode (no plan) judges literal values only, and doesn't see deletions.
- A contract describes the usage seen in its evidence window. A source rarer than the window
  can still be missing; the PR that built the contract lists that as residual risk.
