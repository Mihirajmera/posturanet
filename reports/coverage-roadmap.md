# Coverage roadmap: every finding ends in an outcome PosturaNet can check

Goal: when a scanner reports a finding, PosturaNet always ends it in one of five outcomes, and checks each one after merge:

| Outcome | What PosturaNet does | Today |
|---|---|---|
| **Fixed** | Opens a Terraform PR | 88 controls |
| **Approved fix** | Shows the before and after, a person approves it in the CLI or with a PR checkbox, then it opens the PR | — |
| **New resource** | A PR that adds the missing piece (a flow log, a KMS key, a log bucket) | — |
| **Runbook** | Not a code change (root MFA, account contacts): numbered steps, then re-checks the finding | — |
| **Exception** | Accepted risk with an owner and an expiry date in a YAML file; the finding comes back when it expires | — |

Coverage is **findings that end in an outcome ÷ all findings**. "100%" means none are left as "unsupported". It doesn't mean every finding gets an automatic PR.

## Prowler: the 134 controls with no fix yet

These buckets are my own estimate. They haven't been checked control by control.

| Bucket | Count | Outcome | Work |
|---|---|---|---|
| Small engine work | 10 | Fixed | Mostly catalog rows that need a new locate or verify helper |
| Missing resource | 40 | New resource | A new fix type: resource templates plus a plan-scope check that only allows creating resources |
| Replace or migrate | 25 | Approved fix | A migration PR that creates the new resource next to the old one, with a cutover checklist |
| Cuts access | 27 | Approved fix | Interactive approval in the CLI, plus PR checkboxes |
| Not in code | 32 | Runbook or exception | Runbook files, `exceptions.yaml`, and a re-check |

## Order (each item is its own PR)

1. ✅ **Done (unreleased).** **Outcome labels and `exceptions.yaml`.** Small. Every finding then gets a label, and runbooks and exceptions make the "Not in code" bucket count. This raises the coverage number fastest.
2. ✅ **Done for IAM (unreleased); S3, security groups and the PR checkbox are still to do.** **Approval in the CLI.** For a `risk: medium` row or a stop that needs a person, `fix` shows the diff and asks `Approve? [y/N]`. The approval is recorded in the PR, and a checkbox does the same in CI. This covers the "Cuts access" bucket and the 7 needed stops in the benchmark.
3. **S3.5 and S3.6 on the existing S3 evidence.** Small.
4. **The 10 controls that need small engine work.**
5. **New-resource fix type.** This is the large one. It is a fourth fix type, which AGENTS.md §1.4 doesn't allow today.
6. **Migration PRs** (encrypt an existing RDS instance, and so on).
7. **Wiz ingest.**
8. **CloudFormation, CDK and Pulumi.** AGENTS.md §1.4 doesn't allow these today.

Items 5 and 8 need AGENTS.md §1.4 and PRD §5 changed first. Those files are what any agent working here reads as the rules, so the change is the human's call.

## Not in scope here
Detection stays out. PosturaNet is the layer after the scanner, so no new scanning rules.
