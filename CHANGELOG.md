# Changelog

All notable changes to PosturaNet. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (contract check on every PR)
- `contract check --github-comment <PR>` and the Action's `comment` input (on by default): one PR comment with the result, posted on BLOCK or UNKNOWN and edited on later pushes, so a fixed PR turns it green. A PR that's green from the start gets no comment. If GitHub refuses the comment (fork PR, no `pull-requests: write`), PosturaNet warns and keeps the check's result and exit code. The Action skips the comment when its pinned `version` predates the flag. The example workflow asks for `pull-requests: write`.
- `contract build --all`: a draft contract for every security group in the Terraform state, each from its own flow logs. A group that stops (no flow logs, say) is listed with its reason and doesn't stop the rest; the exit code is the worst one. `--evidence-file` is refused with `--all`, since it holds one group's flows.
- `action.yml` at the repo root, so the Action can be listed on GitHub Marketplace (`uses: Mihirajmera/posturanet@<tag>`). `action/action.yml` keeps working; a test keeps the two identical.

### Changed (one PR per issue across scanners)
- The PR idempotency key and the `posturanet:finding` marker now use the issue, `control@terraform_address`, instead of the scanner's finding id. Security Hub, Prowler, Checkov and Trivy reporting the same problem update one PR instead of opening one each. Open PRs from earlier versions still match on their finding id (FR-28).
- `findings list` and `findings split` take several files. The same control on the same resource (an ARN and its short id count as one) is listed once, with `also <scanner>` on the row and a count in the summary; `split` writes one file for it. JSON rows add `file` (with several files) and `also`. Twin controls such as EC2.13 and EC2.19 are still separate.

## [0.3.0] - 2026-11-12

### Changed (CLI output)
- Text output hangs on one rail: `┌` header, a `◇` line per stage, boxed sections (`Proposed change`, `Result`), and a `└` closing line (`Done. Nothing was changed.`, `Stopped. No PR opened.`). `fix`, `contract build`, `contract check`, `fixes list|show` and `findings list|split|pull-plans` all use it; lists are tables inside a box. A box wider than the terminal drops its right edge instead of wrapping. `--ascii` uses `+ | o * -`. JSON output and the agent-hook reply are unchanged.
- The banner (bare `posturanet`, `init`) is the logo beside a block-letter POSTURANET wordmark (white cloud, blue P; green wordmark with the O and NET in red), then a `Start here` box listing every command with an example. Narrower terminals stack the art, then show the logo only.
- Every command's `--help` ends with copyable examples.

### Added (approval at the terminal)
- When an IAM fix stops only on items a person can confirm (a data-plane service such as S3 whose data actions IAM doesn't track, or `iam:PassRole`), `posturanet fix` at an interactive terminal asks about each one: which extra actions to keep, and whether to keep `iam:PassRole`. It then previews the before/after diff with nothing written and asks `Approve this change?`. An approval goes into the contract like a hand edit (`reviewed_services`, `must_allow` with `source: human`, `status: approved`, `approved_by`, `approved_at`) and into the PR as an `Approved` row. CI, pipes, JSON output, hooks and MCP never prompt; the stop's next steps say approval is available at a terminal. Run records list these items under `approvals`.

### Added (outcomes)
- Every failed finding gets an outcome in `findings list`: `fix`, `runbook`, `exception` (accepted risk) or `none`, and the summary shows coverage (failed findings with an outcome ÷ all failed findings). Passed findings don't count. JSON rows carry `outcome`.
- `.posturanet/exceptions.yaml` (or `--exceptions`): accepted risks with `control`, optional `resource`, `owner`, `reason` and `expires`. An accepted finding isn't split out for fixing; once `expires` passes it's back to its normal outcome, with a note.
- Runbooks for controls that aren't a Terraform change (Account.1, IAM.3, IAM.4, IAM.5, IAM.6, IAM.9, IAM.19, IAM.22): `posturanet fixes show IAM.6` shows the steps.

### Added (connect)
- `posturanet connect`: how to feed Security Hub, Prowler, Checkov and Trivy findings in, and how to wire up coding agents (Claude Code, Cursor, Codex, Copilot, Gemini, Windsurf, Cline, Kiro, Continue, Zed, Goose, any MCP client or AGENTS.md) and the GitHub PR check. `connect <name> --write --repo .` copies the agent or CI files into the repo; it never overwrites a file, and appends to an existing AGENTS.md. The files ship in the wheel.

### Added (fixes)
- 7 attribute fixes, 59 settings controls in all (73 with the evidence fixes): RDS.11 automatic backups, EC2.8 IMDSv2 on instances, EC2.15 no public IPs by default on subnets, EC2.23 Transit Gateway attachment approval, ECR.2 tag immutability, ELB.14 Classic Load Balancer desync mitigation, ElastiCache.3 automatic failover. RDS.11, EC2.8, EC2.15 and ECR.2 are `risk: medium` with a note on what to check first.
- 15 more attribute fixes for controls Prowler, Checkov and Trivy already report, 74 settings controls in all (88 with the evidence fixes): RDS.2 and Redshift.1 no public access, EKS.1 private API endpoint, EC2.25 no public IPs from launch templates, ECS.2 no public IPs on services, SageMaker.3 no notebook root access, CloudFront.8 SNI, ES.1/OpenSearch.1 encryption at rest, ES.3/OpenSearch.3 node-to-node encryption, RDS.35 cluster minor upgrades, S3.12 ACLs off, S3.17 KMS encryption, SNS.1 KMS encryption. Each was checked against the AWS provider source to update in place. All but RDS.35 and the domain encryption rows are `risk: medium`.
- Attribute-fix runs and PRs no longer say "doesn't remove access" for `risk: medium` rows.

### Added (Security Hub)
- Security Hub remediation plans (FR-4c): `posturanet findings pull-plans` reads plans read-only (`GetRemediationsV2`, `ListExposuresByRemediationV2`, `GetFindingsV2`, added to the allowlist and generated IAM policy). Each plan becomes one finding whose controls come from its exposure findings; attribute fixes on the same resource merge into one change and one PR (`RDS.2+RDS.8`). AWS's guidance is kept as data only.
- Security Hub OCSF findings: `get-findings-v2` output and EventBridge "Findings Imported V2" events. Exposure findings name the control findings they link.

### Fixed (ingest)
- A `get-findings-v2` file was read as ASFF because both use a `Findings` key.
- An OCSF compliance finding that passed (`compliance.status` Pass, no `status_code`) was treated as fixable.

### Changed (ingest)
- A scanner check mapped to twin controls with the same fix (ES.1 and OpenSearch.1) uses the first instead of stopping. A Checkov or Trivy check on a resource type the control has no catalog row for is reported as unsupported (CKV_AWS_88 on `aws_instance`).
- Checkov and Trivy now map 56 and 36 checks, to 52 and 31 controls; Prowler findings reach 72.

### Added (ingest)
- Checkov (`-o json`) and Trivy (`config -f json`) reports (FR-4b). 47 Checkov and 31 Trivy checks map to 41 and 24 PosturaNet controls through `ingest/iac_checks.json`, each checked against the scanner's source. The Terraform address in the finding is resolved to the deployed resource through the state; undeployed or ambiguous resources stop.
- Prowler and OCSF findings (FR-4a): `posturanet fix` accepts Prowler `json-ocsf` output, Prowler's ASFF output and OCSF compliance findings. The control comes from `compliance.control`, Prowler's FSBP mapping, or a bundled check map (`ingest/prowler_checks.json`, from Prowler 5.48.0). Only FAIL findings are fixable.
- `posturanet findings list` and `posturanet findings split`: see which findings in a scan PosturaNet can fix, and write one file per finding. `posturanet fix` on a multi-finding file uses the one fixable finding when there is exactly one.

### Added (docs)
- Workflow diagrams in the README and architecture doc: the fix pipeline, the contract check for changes by people and AI agents, and where PosturaNet runs (`docs/media/diagram-*.svg`, drawn by `python docs/media/diagrams.py`).
- README images use absolute GitHub URLs so they also show on PyPI.

## [0.2.0] - 2026-11-06

### Changed (CLI output)
- Color in the terminal, mapped to the design-system tokens: status symbols, bold labels, the result word by state, yellow review notes, a colored diff and blue next-step arrows. Off for pipes, JSON, hooks, `NO_COLOR` and `TERM=dumb`; `FORCE_COLOR` turns it on.
- `Result`, `Unknowns` and `Next` use the 12-column label layout from the design system, with `→` before each next step.
- Contract-check BLOCK hint reads "keep the access" (it covers S3 and IAM now, not only rules).

### Added (docs)
- README demos recorded from real runs: security group fix, IAM fix, a contract-check BLOCK and the Claude Code hook reply (`docs/media/`, regenerated by `python docs/media/make.py`).
- README tip: `python -m posturanet` when the `posturanet` command isn't on PATH.

### Added (check_change for S3 and IAM)
- The contract check (`posturanet contract check`, MCP `check_change`, the Claude Code hook) now judges S3 and IAM contracts as well as security groups, from a plan or offline from the source (US-4, US-7, FR-50, FR-51).
- `s3_public`: BLOCK when a Block Public Access setting is turned off or the block deleted, a bucket policy allows `Principal *`, a policy denies a `must_keep` requester, or (plan only) a cross-account requester loses the grant it had. TLS-only Denies are ignored; other conditional Denies, non-literal flags and, without a plan, a cross-account requester with no grant are UNKNOWN.
- `iam`: BLOCK when a `must_allow` action is no longer allowed or is denied, a `must_remove` wildcard comes back, or the policy is deleted. `NotAction` and grants that exist only under conditions are UNKNOWN.

### Fixed
- `posturanet contract check --source` reported S3 and IAM contracts as invalid; contracts are now loaded by their `kind`.

### Added (Claude Code plugin)
- Installable Claude Code plugin: `/plugin marketplace add Mihirajmera/posturanet`, then `/plugin install posturanet@posturanet`. The repo is its own marketplace (`.claude-plugin/marketplace.json`); the plugin lives in `plugin/` (FR-41).
- `integrations/agents/`: a ready-to-copy folder per coding agent (Cursor, OpenAI Codex, VS Code + Copilot, Gemini CLI, Windsurf/Devin, Cline, Kiro, Continue, Zed, Goose, and an `AGENTS.md` snippet for the rest), each with the MCP server entry and the same PosturaNet rule (FR-40, FR-41).
- The skill now covers S3 public access (S3.1, S3.2, S3.3, S3.8), IAM wildcards (IAM.1, IAM.21), settings controls and `posturanet verify`, not only security groups.

### Changed
- `integrations/cursor/` moved to `integrations/agents/cursor/`, laid out at the paths the files take in your repo; the rule also covers S3, IAM and `propose_fix`.
- `skills/posturanet/` moved to `plugin/skills/posturanet/`, and its `plugin.json` to `plugin/.claude-plugin/plugin.json`.

### Added (R2: IAM least privilege)
- New evidence-backed fix for IAM.1 and IAM.21 on customer-managed `aws_iam_policy`: replaces `"*"` or `service:*` with the actions in use, in `jsonencode`, heredoc or `aws_iam_policy_document` form. Resources, conditions and Deny statements are unchanged (FR-51).
- IAM evidence (FR-16): action-level last-accessed data for the policy and its attached principals; confidence from the policy's age. Data-plane services, `NotAction`, services without action-level data and unattached policies stop the fix. Offline `--evidence-file` export supported.
- Contract kind `iam` with `must_allow`, `must_remove`, `reviewed_services` and `needs_review`; humans approve data-plane services and add actions back.
- `iam:PassRole` is never dropped as unused: IAM doesn't track it, so a wildcard that covers it stops the fix until a human keeps it or reviews `iam`. The PR also notes that last-accessed data counts denied attempts.
- Invariants: the edited policy allows nothing new and still allows every used action. `plan_matches` checks the planned policy JSON.
- Verify watches CloudTrail AccessDenied on removed actions for 72h and opens a revert PR on regression; `--rejects-file` accepts an IAM denied export.
- Read-only allowlist (and generated IAM policy): `cloudtrail:LookupEvents`.

### Added (R2: S3 public access)
- New evidence-backed fix for S3.1, S3.2, S3.3 and S3.8: turns on all four Block Public Access settings, editing the existing `aws_s3_bucket_public_access_block` / `aws_s3_account_public_access_block` or adding one (FR-50).
- S3 evidence (FR-17): bucket exposure (policy status, ACL grants, ownership controls, website), server access logs over the window, and CloudFront origins. Anonymous use, cross-account use through a public policy, a public website or a CloudFront origin without origin access control stops the fix. A bucket that's private today with ACLs disabled needs no logs. Offline `--evidence-file` export supported.
- Contract kind `s3_public` with `must_keep`, `must_block` and `needs_review`; reviewed requesters are approved by moving them to `must_keep`.
- Plan scope accepts exactly one `create` for fixes that add a resource.
- Read-only allowlist (and generated IAM policy): `s3:ListAllMyBuckets`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetBucketOwnershipControls`, `s3:GetBucketWebsite`, `s3:GetBucketLogging`, `cloudfront:ListDistributions`. `list_buckets` and `list_objects_v2` map to their real IAM actions.

### Added (R2: verify and revert)
- `posturanet verify <pr>`: after merge, checks the fix is in the Terraform state, the control passes on it (and in Security Hub when AWS is reachable), and, for security-group fixes, that no source the contract kept was blocked by flow logs during the watch window (FR-31, FR-32). Outcomes: OPENED, REJECTED, NOT APPLIED, STILL FAILING, WATCHING, CONFIRMED, REGRESSED (FR-34).
- `--open-pr` on a regression opens a revert PR that restores the files the fix changed; it stops if any of them changed on the base since the merge (FR-33).
- Fix PR bodies carry a machine-readable verify spec, so verify needs no stored state.
- Offline: `--state`, `--rejects-file`, `--offline`; `--applied-at` and `--window` override the watch window.

### Added (R1.6: attribute fixes)
- New fix type `config_attribute`: 54 catalog rows covering 52 Security Hub controls (`configfix/catalog.json`), e.g. RDS.8 deletion protection, DynamoDB.2 point-in-time recovery, KMS.4 key rotation, CloudTrail.4 log validation, ECR.1 scan on push, EKS.8 audit logs, IAM.7/15/16 password policy, GuardDuty.1, Config.1, EC2.7 EBS default encryption (FR-48).
- HCL attribute editor: sets or inserts literal attributes and nested blocks in place, fmt-aligned, CRLF-preserving. Stops on variables, expressions, `dynamic` or repeated blocks, heredocs, `lifecycle.ignore_changes`, `count`/`for_each` and already-compliant code (drift).
- Validation for attribute fixes: guardrails, fmt, init/validate, plan scope, re-check of the edited code, and `plan_matches` (planned values meet the control; nothing else on the target changes).
- `posturanet fixes list [--service rds] [--format json]` and `posturanet fixes show <control>` (FR-49).
- Account-wide controls (CloudTrail.1, EC2.7, GuardDuty.1, Config.1, Macie.1, IAM password policy) locate the one resource of that type in state.

### Changed
- PR delivery is shared by every fix type (`deliver.github.push_pr`). SG fix PRs are unchanged.

### Added (benchmark v1: S3 and IAM)
- 22 new benchmark cases: 10 for S3 public access (websites, CloudFront with and without OAC, partners via a public policy, scrapers, no logs, an approved unknown requester) and 12 for IAM least privilege (data-plane S3, `iam:PassRole`, actions without action-level data, rare jobs inside and outside the tracking period, a young policy, admin `*`). Baselines: Block always and Skip websites (S3); Used actions only and Remove wildcard (IAM).
- PosturaNet: S3 4 correct, 5 stopped (2 unneeded), 1 outage; IAM 6 correct, 5 stopped (1 unneeded), 1 outage. The best baselines have 3 (S3) and 7 (IAM) outages. Both PosturaNet outages are users invisible in the evidence window; they're listed in `bench/README.md`.
- Verdicts are pinned in `tests/unit/test_bench.py`.

### Added (benchmark and SG contracts)
- Benchmark v0 (`python -m bench`): 13 synthetic security group cases with written ground truth, scoring PosturaNet's real pipeline against three baseline fixes (revoke, private ranges only, allow all observed). Results and PosturaNet's open misses are in `bench/README.md` and `bench/RESULTS.md`. Case 13, `quarterly-dr-drill-approved`, runs the 120-day drill with an approved contract.
- Contracts: `not_kept` list and per-rule `reason`. Rare or one-off internet sources, and internet sources with scan-sized flows (under 2,000 bytes per flow on average), are left out of the fix and listed in the PR as likely scanners. Every other internet source goes to `needs_review`. Moving a `not_kept` source to `must_allow` keeps it across regeneration.
- Evidence: flow-log query sums `bytes` per source; `--evidence-file` rows may carry `bytes`.
- Synthesis: when Z3 times out, an exact nested-prefix solver computes the same optimum, so large fleets (70 CI runners) get a fix instead of a stop.

### Benchmark (PosturaNet)
- 6 → 10 correct of 13; still exposed 2 → 0; one outage left (`quarterly-dr-drill` without an approved contract).

## [0.1.0] - 2026-11-03
First public release.

### Changed (license)
- PosturaNet is licensed under the Functional Source License 1.1 with an Apache 2.0 future license (`FSL-1.1-ALv2`, see `LICENSE.md`): free to use, read and change; no competing commercial products; each release becomes Apache 2.0 two years after it ships.

### Added (R1.5: PosturaNet check)
- `posturanet contract check --source [--file x.tf]`: offline check of the Terraform source against the contracts (no plan, no AWS). Literal inline ingress only; remote modules, `dynamic` blocks and non-literal values are UNKNOWN (US-7).
- `--github-check [--sha]`: publishes a `PosturaNet contract` check run (PASS → success, BLOCK → failure, UNKNOWN → neutral) with annotations on the broken contract line and the resource block (FR-29, US-4 for one repo). Needs `checks: write`.
- Results now carry each broken rule's contract line and the resource's file:line; text output shows `caused by:` per design system §7.
- GitHub Action `command: check`: runs `terraform plan -lock=false` itself (or takes `plan`), or `source-only: "true"` for an offline check; `fail-on-unknown`, `check-run`; output `check-url`. Example workflow in `integrations/github/`.
- `posturanet hook claude-code`: Claude Code PostToolUse hook. After a `.tf` edit it runs the source check and hands a BLOCK reason back to the agent; always exits 0. Wired into the Claude plugin (`skills/posturanet/plugin.json`) and `integrations/claude-code/`.
- MCP `check_change`: `plan_json` is now optional; without it, checks the source, optionally only `files`.
- Cursor rule and MCP config (`integrations/cursor/`), and `integrations/README.md` ("add PosturaNet to your pipeline").
- PRD: per-repo contract checks are in Community; the org-wide gate stays in Team (R4).
- Terminal logo: the PosturaNet logo (cloud, P, arrow) in half-block pixels with the brand gradient, shown by bare `posturanet` and `posturanet init` (on stderr). Only at an interactive terminal: never in JSON, pipes, CI, MCP or hooks. `NO_COLOR` drops color, non-UTF-8 terminals get a text-only version, `POSTURANET_NO_BANNER=1` turns it off.

### Added (R1: SG contracts)
- Read-only AWS layer (`aws/readonly.py`): every call goes through an allowlist; anything else raises `MutatingCallBlocked`. `posturanet init` prints the IAM policy generated from the same list (NFR-2, FR-47 partial).
- Evidence: VPC flow logs via CloudWatch Logs Insights, scoped to the security group's ENIs, chunked by 7 days, with a fail-closed 10,000-row cap. Offline `--evidence-file` JSON source. Confidence (high/medium/low/none), coverage and max gap, periodicity (daily/weekly/monthly/irregular/rare/one_off) with peak-hour detection (FR-11..FR-15).
- Behavior contracts: draft builder with default `must_deny` (world access on sensitive and exposed ports), YAML store per design system §5 (header, key order, flow-style rules, quoted account id). Approved contracts are used as-is and never overwritten; owner/ref edits survive regeneration (FR-14).
- Z3 synthesis of the minimal ingress rule set: replaces only open rules, keeps traffic the remaining rules already allow, supernets up to /16 internal and /24 public, quota-aware, lexicographic objective (exposure, then rule count). UNSAT and solver timeouts stop (FR-18).
- HCL rewrite of inline `ingress {}` blocks with literal values, fmt-clean output (checked against real `terraform fmt`), CRLF preserved. Dynamic blocks, non-literal values, block comments and separate rule resources stop (FR-20).
- Drift check from state ingress before synthesis, and from the plan's `before` during validation (FR-9).
- Validation runner in a temp copy: guardrails, `fmt -check`, `init` + `validate`, `plan -lock=false` + `show -json`, plan scope (target only, update in place), drift, plan-matches-fix, contract invariants (Z3 for allow, exact set checks for deny, with `model_scope`), finding re-check for EC2.13/14/18/19/53/54, optional tflint/checkov. PASS / FAIL / INCOMPLETE; anything but PASS opens no PR (FR-21..FR-26).
- PR delivery through the GitHub REST API: idempotency key + finding marker (one open PR per finding; same key → no writes, new key → update), base-branch content check, `posturanet/...` branches only, max open PRs, PR title/body/labels per design system §6, safety contract YAML (FR-27, FR-28, FR-30).
- S3 backend: `backend "s3"` block parsing and `s3:GetObject` through the read-only client; state kept in memory only (FR-5).
- CLI: `fix [--dry-run | --open-pr] [--evidence-file] [--window 90d]`, `contract build`, `contract check --plan` (exit 5 on BLOCK), `init`, `mcp`. Text output shows observed sources and the proposed diff.
- MCP server (stdio, MCP SDK 2.x) with read-only `explain_finding`, `propose_fix`, `check_change` (FR-40). Claude skill `skills/posturanet/SKILL.md` (FR-41). Composite GitHub Action `action/` (FR-39 partial).
- 129 tests, including hypothesis properties for synthesis and the Z3 allow check (zero wrongly-reported-safe), a no-mutating-AWS-calls test, a static "no boto3 outside `aws/`" test, and a real `terraform fmt` integration test.

### Fixed
- Flow-log query no longer filters on `flowDirection`, which exists only in custom log formats. On the default format it returned zero inbound flows, so every rule looked unused and could be proposed for removal. Inbound is now matched by `dstAddr` against the ENIs' own IPs, and an unparseable row stops the run instead of being dropped.

### Added (testing)
- `.github/workflows/posturanet.yml`: ruff, mypy, pytest (Python 3.11 and 3.12, real terraform for the fmt test), shellcheck on the Action entrypoint, and an offline smoke run.
- `sandbox/`: a throwaway Terraform repo for end-to-end tests: SG open on 22, an internal client, default-format VPC flow logs with 120-day retention, a read-only role, traffic scripts and a day-by-day test plan.

### Changed
- `fix` without `--dry-run` now runs the full pipeline (`check` mode); `--open-pr` delivers. `--dry-run` never calls AWS, GitHub or `terraform plan`, and writes nothing.
- A dry run without `--evidence-file` stops after locate, with next steps instead of "arrives in R1".
- `StageStop` can mark a stop as unknown (`?`, e.g. no evidence) and carry its own exit code (4 for validation FAIL).

### Not in R1 (tracked)
- Athena flow-log mode and `evidence.max_scan_gb`; IPv6 synthesis; `aws_security_group_rule` / `aws_vpc_security_group_ingress_rule` resources; `verify`, check runs (FR-29), freeze windows; MCP `open_fix_pr`; `init` writing config.

### Added (R0: dry-run skeleton)
- Package skeleton (`src/posturanet`), Pydantic v2 models for findings, locations, config and run records.
- ASFF ingest: Security Hub JSON → OCSF-aligned `Finding`, plus manual `sg-…` resource ids (FR-1, FR-3, FR-4).
- Locator v0: local Terraform state v4 → address (modules, index keys) → `file:line` via a minimal HCL scanner → owners from CODEOWNERS (FR-5..FR-8). Remote modules, S3 backend, duplicates and missing resources stop the run.
- `posturanet fix <target> --dry-run [--repo] [--state] [--format text|json] [--ascii]`, output per the design system. Exit codes 0 / 2 / 3.
- Synthetic fixtures (`tests/fixtures/`) and 36 tests.

### Notes
- Drift is reported as unknown until `terraform plan` lands in R1.
- The state fixture is named `state.fixture.json` so the repo's `*.tfstate` ignore rule stays in force.
