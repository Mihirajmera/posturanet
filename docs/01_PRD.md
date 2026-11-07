# PosturaNet: Product Requirements Document (PRD)

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-02 |
| Owners | The three co-founders |
| Status | Active. This is the source of truth for *what* v1 does. |
| Related | [02_ARCHITECTURE_AND_DATA.md](02_ARCHITECTURE_AND_DATA.md) · [04_DESIGN_SYSTEM.md](04_DESIGN_SYSTEM.md) · [../AGENTS.md](../AGENTS.md) · [Company brief v2](../../docs/posturanet-brief-v2/PosturaNet_Company_Brief_v2.pdf) · [Strategy brief v1.1](../../docs/POSTURANET_STRATEGY_BRIEF_v1.1.md) |

Requirement IDs (`FR-`, `NFR-`) are stable. Reference them in code comments, tests and PRs. When scope changes, update this file in the same PR.

---

## 1. Product summary

**PosturaNet is a remediation agent for AWS + Terraform teams.** It takes a security finding the team already has, finds the Terraform and team that own the resource, learns what actually uses the resource from flow logs and CloudTrail, records that as a **behavior contract**, and opens a pull request with the smallest fix that keeps every observed behavior working. After the fix is confirmed, it writes signed audit evidence.

It runs **in the customer's CI or on an engineer's machine**, with a **read-only** AWS role and **the customer's own LLM**. It never writes to production. Humans review and merge every change.

**One line:** *Fixes cloud security issues without breaking prod, and proves it to your auditor.*

## 2. Problem

When a finding lands (e.g. "SG allows 0.0.0.0/0 on port 22"), the engineer has to:
1. **find the owner**: which repo, file, module and team;
2. **find what uses it**: logs are hard to query, so this step is usually skipped;
3. write the fix, which takes minutes;
4. deal with `terraform plan` noise from unrelated drift;
5. get it through review ("are you sure nothing uses this?");
6. deploy it, sometimes breaking an unknown dependency;
7. revert it, after which the finding is marked "risk accepted" and never fixed.

Writing the fix is cheap. Everything around it is expensive and risky, so backlogs grow. Vendors now generate fix PRs (Wiz, Gomboc, Cloudgeni and others), but their public material doesn't show them proving what the change *preserves*. That proof is PosturaNet's focus.

## 3. Users and personas

| Persona | Role | Needs | Success for them |
|---|---|---|---|
| **Dev**: DevOps / SRE engineer | Daily user | Small diffs, clear reasons, no PR flood | Merges a PosturaNet PR in minutes without asking anyone |
| **Pat**: Platform / cloud-security lead | Champion | Backlog closed safely; a gate on risky changes | Findings close and nothing breaks |
| **Cass**: CISO / Head of Security | Buyer | Confirmed closure, low effort | Closure numbers they can report |
| **Gia**: GRC / compliance lead | Buyer | Evidence without screenshots | Signed evidence mapped to controls |
| **Ava**: AI coding agent (Claude Code, Cursor) | Machine user | A way to check Terraform changes are safe | Calls `check_change` before proposing infrastructure edits |

## 4. Goals and non-goals

### Goals (v1)
- G1: Turn a supported AWS finding into a reviewable, validated Terraform PR with usage evidence.
- G2: Never report a change as safe when it isn't (target: **zero wrongly reported "safe" fixes**).
- G3: Install to first PR in under 15 minutes on a prepared repo, without founder help.
- G4: Generate behavior contracts that teams approve and keep.
- G5: Produce signed, control-mapped evidence for confirmed fixes (paid).
- G6: Support license-based monetization (Community / Team / Business).

### Non-goals (v1). Don't build these.
- Writing to production or applying Terraform.
- A dashboard or hosted multi-tenant SaaS.
- Detection rules beyond re-checking a known finding.
- Multi-cloud, CloudFormation, CDK, Pulumi, Terragrunt, remote modules.
- More than three evidence-backed fix types (SG ingress, S3 public access, IAM least privilege). The attribute-fix catalog (FR-48) is not a fix type of this kind: it only sets literal settings that remove no access, and grows by catalog rows.
- Founder-delivered or managed services.

## 5. Scope by release

| Release | Contents | Target |
|---|---|---|
| **R0: Dry-run skeleton** | Package layout, OCSF finding model, ASFF ingest, locator v0, `posturanet fix --dry-run` on fixtures | Week 1 |
| **R1: SG contracts** | Flow-log collector, SG contract builder, Z3 synthesis, validation pipeline, PR delivery, CLI + GitHub Action, Claude skill, MCP (read-only tools). **Built** (see CHANGELOG for what's deferred) | Weeks 2–3 |
| **R1.5: PosturaNet check** | Contract check where teams already work: `PosturaNet contract` check run on PRs (FR-29, US-4 for one repo), Action `check` mode, offline source check, Claude Code hook, Cursor rule, MCP `check_change` source mode (US-7). **Built** | Week 3 |
| **R1.6: Attribute fixes** | `config_attribute` fix type: 54 catalog rows covering 52 Security Hub controls across RDS, Aurora, DocumentDB, Neptune, DynamoDB, KMS, ELB, CloudTrail, ECR, EKS, ElastiCache, DMS, Redshift, SQS, API Gateway, Kinesis, Network Firewall, Athena, EBS, S3, MSK, GuardDuty, Config, Macie, IAM password policy and CodeBuild (FR-48). `posturanet fixes list|show` (FR-49). **Built** | Week 3 |
| **R2: Verify + evidence** | Post-merge verification and revert PR (**built**: `posturanet verify`, FR-31..FR-33), S3 public-access fix (**built**: S3.1, S3.2, S3.3, S3.8, FR-17, FR-50), IAM least privilege (**built**: IAM.1, IAM.21, FR-16, FR-51) and the safety benchmark (**built**: 35 cases across SG, S3 and IAM, `bench/`), signed OSCAL evidence (pro) | Weeks 4–5 |
| **R3: IAM + benchmark** | CloudTrail / last-accessed collector, IAM contract and least-privilege synthesis, benchmark v0 (20 cases), public launch | Week 6 |
| **R4: Team plan** | Org-wide contract gate (one config for every repo), event triggers, license keys, Stripe, Slack notifications | Weeks 7–9 |
| **R5: Living contracts** | New-behavior and drift PRs, periodicity, Prowler/ASR input, policy packs | Weeks 10–12 |

## 6. User stories with acceptance criteria

**US-1. Fix one finding from the CLI** (Dev)
*As an engineer, I run `posturanet fix <finding-or-resource>` and get a PR with evidence.*
- AC1: Prints owner, file:line, evidence summary, proposed change and validation results.
- AC2: With `--dry-run`, makes no AWS calls beyond reads, creates no branch or PR, and writes nothing to the repo except optional output files.
- AC3: With `--open-pr`, opens exactly one PR. Running again opens no duplicate.
- AC4: If any required step is UNKNOWN or fails, opens no PR and prints why plus what to do next.

**US-2. Generate and approve a behavior contract** (Pat)
- AC1: `posturanet contract build <resource>` writes `posturanet/contracts/<address>.yaml` with window, source, observations, confidence and `status: draft`.
- AC2: Every one-off or rare source is flagged for human review and never dropped silently.
- AC3: Approving is a normal PR merge that changes `status` to `approved` with `approved_by`.

**US-3. Automatic fix from Security Hub** (Pat, Team plan)
- AC1: A Security Hub finding event triggers the Action via EventBridge → `repository_dispatch`.
- AC2: Rate limits and freeze windows from config are respected.

**US-4. Contract gate on a Terraform PR** (Pat, Team plan)
- AC1: On a PR touching `*.tf`, a "PosturaNet contract" check run reports PASS or BLOCK.
- AC2: A BLOCK names the exact contract line that would break and the planned change that breaks it.

**US-5. Verify and revert** (Dev)
- AC1: After apply, PosturaNet re-checks the finding and watches for regression signals for the tier's window.
- AC2: On a regression, it opens a revert PR within one run and marks the outcome REGRESSED.

**US-6. Audit evidence** (Gia, Business plan)
- AC1: Only CONFIRMED outcomes produce evidence records.
- AC2: `posturanet evidence export --period 2026Q4 --framework soc2` writes OSCAL assessment-results JSON plus a readable summary.
- AC3: Records are hash-chained and signed, and tampering is detected by `posturanet evidence verify`.

**US-7. AI agent checks a change** (Ava)
- AC1: The MCP tool `check_change` accepts a plan JSON, or checks the Terraform source (optionally only edited files), and returns PASS/BLOCK/UNKNOWN with reasons.
- AC3: In Claude Code, a hook checks every `.tf` edit and hands a BLOCK reason back to the agent before it continues.
- AC2: Read-only tools need no confirmation. `open_fix_pr` requires explicit user confirmation.

## 7. Functional requirements

### Ingest
- **FR-1** Accept AWS Security Hub findings in ASFF (file, stdin, or API by finding ID).
- **FR-2** Accept manual input by resource ID or ARN plus control ID.
- **FR-3** Normalize to the internal OCSF-aligned `Finding` model. Reject findings missing required fields, with a clear error.
- **FR-4** Record provenance (raw sha256, schema version).

### Locate
- **FR-5** Find Terraform state using backend config (v1: S3 backend; local state file for tests).
- **FR-6** Map the resource ID to a state address, supporting `module.*`, `count` and `for_each` keys.
- **FR-7** Map the address to source file:line for local modules. Remote modules → UNKNOWN.
- **FR-8** Find the owner from CODEOWNERS, falling back to recent committers.
- **FR-9** Detect drift on the target resource. If it has drifted → stop, report, no PR.
- **FR-10** Return candidates with confidence and reasoning. Never a single unexplained guess.

### Evidence and contracts
- **FR-11** Collect SG usage from VPC Flow Logs (CloudWatch Logs Insights or Athena) for the SG's ENIs.
- **FR-12** Compute the confidence level (high / medium / low / none) from data coverage (rules in the architecture doc §6).
- **FR-13** Detect periodicity (daily, weekly, one-off) and flag rare sources for review.
- **FR-14** Build a `BehaviorContract` (draft). Load approved contracts from the repo.
- **FR-15** Confidence `none` → produce a report only, never a PR.
- **FR-16** (R2) IAM usage from action-level `GenerateServiceLastAccessedDetails` on the policy (about 400 days of tracking). Confidence from the policy's age: 60+ days high, 14+ medium, else low; no attached principal → unknown. CloudTrail and Access Analyzer inputs are later work.
- **FR-17** (R2) S3 usage from server access logs / CloudTrail data events and CloudFront origins.

### Synthesis
- **FR-18** Calculate the minimal SG ingress rule set satisfying `must_allow` and `must_deny` (Z3), within AWS rule quotas.
- **FR-19** Prefer deterministic templates. Use the LLM only for long-tail cases, and always within policy and validation.
- **FR-20** Output a Terraform diff limited to the target resource.

### Attribute fixes
- **FR-48** For controls in `configfix/catalog.json`, set literal attributes on the located resource in place, with no usage evidence or contract, because the catalog only holds settings that remove no access or traffic. Each row names the control, resource type, changes (`set`, `at_least`, `one_of`, `includes`), preconditions (`when`) and scope (`resource`, or `account` for the one resource of that type in state). Fail closed on non-literal values, `dynamic` or repeated blocks, heredocs, `lifecycle.ignore_changes` covering the attribute, `count`/`for_each` instances, and code that already complies (drift). Validation: guardrails, fmt, init/validate, plan scope, re-check of the edited code, and a plan check that the planned values meet the control and nothing else on the target changes. A row is added only with a round-trip test and a real `terraform fmt` pass.
- **FR-50** For S3.2, S3.3 and S3.8, turn on all four Block Public Access settings on the bucket's `aws_s3_bucket_public_access_block`, editing it in place or adding one next to the bucket; for S3.1, the same on `aws_s3_account_public_access_block`. Only when the evidence (FR-17) shows no anonymous use, no cross-account use through a public policy, no static website and no CloudFront origin without origin access control on a public bucket. A bucket that is private today with ACLs disabled needs no logs; a public one, or one with ACLs enabled, needs server access logs over the window (confidence rules as FR-12). S3.1 needs every bucket in the account private with ACLs disabled. Requesters PosturaNet can't tie to an account go to `needs_review` in an `s3_public` contract; a human approves them by moving them to `must_keep`. Plan scope allows exactly one `create` of the new block, or an in-place update. S3.19 (access points) is out: the setting forces replacement.
- **FR-51** For IAM.1 (`"*"`) and IAM.21 (`service:*`) on customer-managed `aws_iam_policy` resources, replace each targeted wildcard with the actions the evidence (FR-16) shows were used, in `jsonencode`, heredoc JSON or `aws_iam_policy_document` form. Resources, conditions and Deny statements are never changed; explicit actions and partial wildcards stay. Stop on `NotAction`, on a used service with no action-level data, on a statement left with no actions, and on data-plane services (S3, Lambda, DynamoDB, SQS, SNS, Kinesis, Bedrock and others, whose data actions aren't tracked) until a human lists them in `reviewed_services` of an approved `iam` contract. Humans add actions back with `must_allow` (`source: human`). `iam:PassRole` isn't in last-accessed data, so removing a wildcard that covers it stops until a human keeps it in `must_allow` or lists `iam` in `reviewed_services`. Last-accessed data counts denied attempts as use; the PR states that kept actions may include some another control already denies. Invariants: the new statements allow nothing the old ones didn't, and every used action is still allowed. `plan_matches` reads the planned policy JSON. Verify watches CloudTrail AccessDenied for the attached principals on removed actions for 72h.
- **FR-49** `posturanet fixes list [--service] [--format json]` and `posturanet fixes show <control>` list every control PosturaNet fixes and exactly what each changes.

### Validation (all required, fail closed)
- **FR-21** `terraform fmt -check` and `validate`.
- **FR-22** tflint and checkov: no new high-severity issue.
- **FR-23** Plan scope: changes only to the target, no undeclared destroy or replace.
- **FR-24** Contract invariants hold on the planned configuration (Z3).
- **FR-25** Re-check the source finding against the planned configuration.
- **FR-26** Customer guardrails: allowed paths, PR rate limit, freeze windows.

### Delivery
- **FR-27** Create a branch and PR with the body defined in the design system (evidence table, safety contract, validation, residual risk, unknowns, reviewer checklist, revert notes).
- **FR-28** Idempotency key `sha256(finding_id + contract_sha + diff_sha)`. Never open duplicate PRs.
- **FR-29** Publish a check run with the summary.
- **FR-30** Never merge. Never apply.

### Verification
- **FR-31** After apply, re-run the finding check on live state.
- **FR-32** Watch REJECT (network) or AccessDenied (IAM) signals from contracted sources for the tier window (24h / 72h / 7d).
- **FR-33** On a regression → revert PR, notify the owner, set outcome REGRESSED.
- **FR-34** Set CONFIRMED only when FR-31 passes and no regression occurred in the window.

### Evidence (pro)
- **FR-35** Signed, hash-chained `EvidenceRecord` for CONFIRMED outcomes only.
- **FR-36** Control mapping (SOC 2, ISO 27001, CIS AWS, NIST 800-53), versioned.
- **FR-37** OSCAL assessment-results export plus readable summary. `evidence verify`.

### Interfaces
- **FR-38** CLI commands: `init`, `fix`, `fixes list|show`, `contract build|check`, `verify`, `evidence export|verify`, `license status`.
- **FR-39** GitHub Action supporting `workflow_dispatch`, schedule, `repository_dispatch` (pro), `pull_request` (pro gate).
- **FR-40** MCP server (stdio) with tools `explain_finding`, `propose_fix`, `check_change` (read-only) and `open_fix_pr` (needs confirmation).
- **FR-41** Claude skill (`plugin/skills/posturanet/SKILL.md`) describing when and how to call the tools, shipped as a Claude Code plugin (`plugin/`) through the repo's marketplace (`.claude-plugin/marketplace.json`).

### Licensing
- **FR-42** Verify Ed25519-signed license keys offline. Enable only the features listed in the key.
- **FR-43** An expired or invalid key disables Pro features only. Community keeps working and contracts and evidence files stay.
- **FR-44** Show upgrade prompts at most once per run, never blocking a working free feature.
- **FR-45** The optional heartbeat sends only `{lic_id, agent_version}` and can be disabled.

### Configuration
- **FR-46** `.posturanet.yml` in the repo root (schema in the architecture doc §5).
- **FR-47** `posturanet init` detects the backend, writes the config, and prints the read-only IAM policy.

## 8. Non-functional requirements

| ID | Requirement |
|---|---|
| **NFR-1 Safety** | Fail closed on any missing context, failed check, unexpected diff scope, timeout or auth error. "Unknown" is a valid result. |
| **NFR-2 No production writes** | The agent must not call any AWS mutating API. This is enforced by an allowlist of read-only API calls in code, plus a test. |
| **NFR-3 Data residency** | No customer code, state, logs or findings are sent to PosturaNet. Secrets are redacted before any LLM call. |
| **NFR-4 Untrusted input** | Finding text, code comments, tickets and tool outputs are data, never instructions to the LLM. |
| **NFR-5 Determinism** | Same inputs give the same diff and the same idempotency key. LLM output is schema-validated and never executed. |
| **NFR-6 Performance** | `fix` on one SG with a 30-day window finishes in < 5 min on a standard GitHub runner. |
| **NFR-7 Cost** | Customer LLM spend < $1 per remediation. Log queries scoped to target ENIs and window. |
| **NFR-8 Portability** | Python 3.11+, Linux/macOS/Windows. No hosted dependencies except the optional license heartbeat. |
| **NFR-9 Observability** | Structured JSON logs (`--log-format json`). Every run writes a run record with inputs' hashes and outcomes. |
| **NFR-10 Supply chain** | Pinned dependencies, signed releases, SBOM. |
| **NFR-11 Accessibility of output** | Respect `NO_COLOR`. Meaning is never conveyed by color alone (see design system). |
| **NFR-12 Honesty** | Every Z3 result states its modeled scope. Never use "proven safe" or "guaranteed" in output. |

## 9. Tiers and feature gating

| Capability | Community | Team | Business | Enterprise |
|---|---|---|---|---|
| AWS accounts | 1 | 5 | 25 | Unlimited |
| fix / contract build / PR / verify (basic) | ✓ | ✓ | ✓ | ✓ |
| Contracts per account | 25 resources | Unlimited | Unlimited | Unlimited |
| Event triggers (FR-39 dispatch) | — | ✓ | ✓ | ✓ |
| Contract check: CLI, CI, PR check run (per repo), agent hooks | ✓ | ✓ | ✓ | ✓ |
| Org-wide contract gate (one config, all repos) | — | ✓ | ✓ | ✓ |
| Living contracts (R5) | — | ✓ | ✓ | ✓ |
| Monitoring window | 24h | 72h | 7d | Custom |
| Slack | — | ✓ | ✓ | ✓ |
| Signed OSCAL evidence | — | — | ✓ | ✓ |
| Policy packs, auto-merge for low-risk fixes | — | — | ✓ | ✓ |
| Org MCP policy for AI agents | — | — | ✓ | ✓ |
| Control plane, SSO | — | — | — | ✓ |

Prices are on the website and never in code. Feature flags in the license key: `triggers`, `gate`, `living`, `slack`, `evidence`, `policy`, `automerge`, `org_mcp`, `accounts_max`, `contracts_max`.

## 10. Success metrics

| Metric | Target |
|---|---|
| Wrongly reported "safe" | **0** (release blocker) |
| Install → first PR (prepared repo) | < 15 min |
| PR merge rate | > 70% early, > 80% later |
| Evidence coverage (confidence ≥ medium) | Measure in the first 10 accounts |
| Confirmed remediations / active customer / month | North star |
| Repeat use | ≥ 2–3 customers by week 9 |
| Founding customers | ≥ 3 by week 3 |

## 11. Release criteria (every release)
- All acceptance criteria for the included stories pass.
- Zero wrongly-reported-safe cases on the benchmark and fixtures.
- The no-mutating-AWS-calls test passes (NFR-2).
- Docs updated: this PRD, the architecture doc, and the CHANGELOG.

## 12. Risks
| Risk | Mitigation |
|---|---|
| Logs disabled in many accounts | Confidence `none` → report plus enablement guide. Measure the rate early. |
| Terraform layouts too varied | A narrow supported layout. Detect and stop on the rest. |
| A competitor adds usage evidence | Speed, benchmark, audit evidence, public source code (FSL blocks competing use), per-customer contracts |
| Wrong mapping | Confidence plus reasoning, UNKNOWN allowed, benchmark mapping precision |

## 13. Open questions
1. Which finding class appears most in the 30+ interviews: SG, S3 or IAM? (Pick R1 accordingly. SG is the current default.)
2. CloudWatch Logs Insights or Athena as the default flow-log path?
3. Should the Community contract limit be 25 resources or per-account unlimited with no gate?
4. Evidence signing key: customer-generated (default) or KMS-backed (Enterprise)?
