# How PosturaNet compares

Most cloud security tools can now turn a finding into a fix. Many open a Terraform pull request. PosturaNet does that too, but it is built for a different question: **is this fix safe to merge, and how will we know if it wasn't?**

This page is based on each vendor's public documentation and blog posts as of November 2026. If something below is out of date, open an issue and we'll correct it.

## What PosturaNet does differently

| | PosturaNet | Typical approach |
|---|---|---|
| **Evidence before narrowing** | Reads what actually uses the resource (VPC flow logs for security groups, S3 access logs for public access, IAM last-accessed data and CloudTrail for policies) and keeps every observed behavior. Refuses with reasons when the evidence is thin. | Runtime data is used to prioritize findings or judge exploitability. The fix itself follows a best-practice template. |
| **Smallest rule set** | Computes the narrowed security group rules with a solver (Z3) and checks the change against the recorded behavior contract. | Template or LLM-generated change, reviewed by a person. |
| **After merge** | `posturanet verify` re-checks the finding and watches for blocked traffic or `AccessDenied` from kept sources for as long as the least frequent of them needs to come back (72 hours to 35 days). On a regression it opens a revert PR. | The next scan shows the finding closed. Rollback means restore instructions or a manual step. |
| **Where it runs** | In your CI, with a read-only AWS role. No vendor GitHub app with write access; Terraform state never leaves your environment. | A SaaS GitHub app with write access, or Terraform state sent to the vendor. Some tools change live resources directly, which causes drift from your Terraform. |
| **Other agents' changes** | A `PosturaNet contract` check gates security group, S3 and IAM changes written by people or coding agents (Claude Code, Cursor, Copilot and others via MCP) before they merge. | Posture context for agents, without a usage-backed verdict on the change. |

## Works with what you already run

PosturaNet is not a scanner. It reads findings from Security Hub (including its remediation plans), Prowler, Checkov, Trivy, and Wiz, Orca and Prisma Cloud JSON exports. Keep your detector, and let PosturaNet do the fixing.

- **AWS Security Hub remediation plans** say what to change. PosturaNet turns a plan into one reviewed PR against your own Terraform modules, with evidence, and verifies it after merge.
- **Prowler** finds the issue and can suggest a fix. PosturaNet adds the usage evidence, the behavior contract and the post-merge watch.
- **CNAPPs** (Wiz, Orca, Cortex Cloud, Defender for Cloud, Tenable) can open fix PRs from their console. PosturaNet keeps the evidence and the change in your own CI, and can gate those PRs with its contract check.

## What PosturaNet doesn't do

- It doesn't detect issues. Bring a scanner.
- It never applies changes. A person merges every PR, and your pipeline applies it.
- AWS only today, with Terraform, CloudFormation (and SAM), CDK and Pulumi.
- Evidence describes what was observed in the window. A job that runs less often than the window can be missed, which is why every PR lists its unknowns and residual risk.
