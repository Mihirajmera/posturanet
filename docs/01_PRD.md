# PosturaNet: Product Requirements Document (PRD)

| | |
|---|---|
| Version | 2.0 (pivot) |
| Date | 2026-11-17 |
| Owners | The three co-founders |
| Status | Active. This is the source of truth for *what* PosturaNet does. v1.0 (2026-11-02) described an AWS + Terraform remediation agent; v2.0 widens it to the remediation layer for every detector, IaC tool and AI coding agent. |
| Related | [02_ARCHITECTURE_AND_DATA.md](02_ARCHITECTURE_AND_DATA.md) · [04_DESIGN_SYSTEM.md](04_DESIGN_SYSTEM.md) · [../AGENTS.md](../AGENTS.md) · [Company brief v2](../../docs/posturanet-brief-v2/PosturaNet_Company_Brief_v2.pdf) · [Strategy brief v1.1](../../docs/POSTURANET_STRATEGY_BRIEF_v1.1.md) |

Requirement IDs (`FR-`, `NFR-`) are stable. Reference them in code comments, tests and PRs. When scope changes, update this file in the same PR.

---

## 1. Product summary

**PosturaNet is the remediation layer for cloud security.** It sits after every detector (Security Hub, Prowler, Checkov, Trivy, and the platforms that feed them) and after every AI coding agent. For each finding it:
1. finds the code and team that own the resource;
2. learns what really uses the resource, from flow logs and CloudTrail;
3. records that as a **behavior contract**;
4. opens a pull request with the smallest fix that keeps every observed behavior working;
5. after merge, verifies the fix held, reverts on regression, and writes audit evidence.

The same contracts then check every later change, from a person or an agent, so a fix stays fixed.

It runs **in the customer's CI or on an engineer's machine**, with a **read-only** AWS role and **the customer's own LLM**. It never applies changes. Humans review and merge every PR.

**One line:** *Fixes cloud security issues without breaking prod, keeps them fixed, and proves it to your auditor.*

**The promise to every customer:** whatever scanner and whatever IaC they use, every failed finding ends in an outcome:
- a fix PR;
- a runbook;
- an accepted exception, with an owner and an expiry;
- or a stated reason why not yet.

Nobody leaves empty-handed.

## 2. Problem

Detection is solved; teams have more findings than they can close. When a finding lands (e.g. "SG allows 0.0.0.0/0 on port 22"), the engineer has to:
1. **find the owner**: which repo, file, module and team;
2. **find what uses it**: logs are hard to query, so this step is usually skipped;
3. write the fix, which takes minutes;
4. deal with plan noise from unrelated drift;
5. get it through review ("are you sure nothing uses this?");
6. deploy it, sometimes breaking an unknown dependency;
7. revert it, after which the finding is marked "risk accepted" and never fixed.

Writing the fix is cheap. Everything around it is expensive and risky, so backlogs grow. Two things make it worse now:
- **Several detectors report the same problem**, each opening its own ticket or PR.
- **AI coding agents change infrastructure** faster than anyone reviews it, and quietly undo last quarter's fixes.

Vendors now generate fix PRs (Wiz, Gomboc, Cloudgeni and others). Their public material doesn't show them doing three things, which are PosturaNet's focus:
- proving what a change *preserves*;
- keeping it fixed against later edits;
- running read-only in the customer's CI.

## 3. Users and personas

| Persona | Role | Needs | Success for them |
|---|---|---|---|
| **Dev**: DevOps / SRE engineer | Daily user | Small diffs, clear reasons, no PR flood | Merges a PosturaNet PR in minutes without asking anyone |
| **Pat**: Platform / cloud-security lead | Champion | Backlog closed safely; a gate on risky changes | Findings close, nothing breaks, nothing reopens |
| **Cass**: CISO / Head of Security | Buyer | Confirmed closure, low effort | Closure numbers they can report |
| **Gia**: GRC / compliance lead | Buyer | Evidence without screenshots | Signed evidence mapped to controls |
| **Ava**: AI coding agent (Claude Code, Cursor, others) | Machine user | A way to check infrastructure changes are safe | Calls `check_change` before proposing infrastructure edits, and fixes its own change on BLOCK |

## 4. Goals and non-goals

### Goals
- G1: Turn any supported finding, from any supported detector, into a reviewable, validated PR with usage evidence, in the customer's own IaC tool.
- G2: Never report a change as safe when it isn't (target: **zero wrongly reported "safe" fixes**).
- G3: Install to first PR in under 15 minutes on a prepared repo, without founder help.
- G4: **Every failed finding gets an outcome** (fix, runbook, accepted exception, or a reason), whatever the scanner or IaC tool. Coverage is shown on every run.
- G5: **Be the safety check for every infrastructure change**: contracts checked on every PR and every AI-agent edit, so fixes stay fixed.
- G6: **Contracts become the system of record** for what each resource must keep allowing.
- G7: **Learn which fixes break production** from verify outcomes, through the opt-in outcome share (FR-45a).
- G8: Produce signed, control-mapped evidence for confirmed fixes (paid).
- G9: Revenue from software and partners: free CLI and Action, paid governance (Pro).

### Coverage targets (what "no customer leaves empty-handed" means)
| Area | Today | Target |
|---|---|---|
| Detectors | Security Hub (ASFF, OCSF), Prowler, Checkov, Trivy, Security Hub remediation plans; Wiz, Orca, Prisma Cloud JSON exports (R5: parsers built; mappings come from the export or the customer) | Wiz, Orca, Prisma Cloud CSV once their columns are documented or a design partner shares one; rules are never guessed |
| IaC tools | Terraform; CloudFormation and SAM (R6); AWS CDK in TypeScript and Python (R7); Pulumi in TypeScript, Python, Go and YAML (R8, merging) | + other CDK and Pulumi languages |
| Same problem, many reports | One PR per issue across scanners and related controls | Kept as new detectors and IaC tools arrive |
| Contracts | Security groups, S3 buckets, IAM policies, for the whole state (`contract build --all`) | Every supported resource in every supported IaC tool |
| Outcomes | fix / runbook / exception / none on every failed finding | Every control a supported detector reports has a non-`none` outcome |

### Non-goals. Don't build these.
- Applying changes to production or merging PRs. (CloudFormation change-set *previews* are an opt-in exception that never executes; see NFR-2 and AGENTS.md rule 1.)
- Detection: PosturaNet re-checks a known finding but never competes with the detectors it sits behind.
- A hosted service that holds customer code, state, logs, contracts or findings. Hosted parts are limited to license keys and the opt-in outcome share's anonymous counts.
- Multi-cloud (GCP, Azure) and Terragrunt, for now.
- More than three evidence-backed fix types (SG ingress, S3 public access, IAM least privilege), decided again on 2026-11-14: deepen these first. The attribute-fix catalog (FR-48) is not a fix type of this kind: it only sets literal settings that remove no access, and grows by catalog rows.
- Founder-delivered or managed services.

## 5. Scope by release

| Release | Contents | Status |
|---|---|---|
| **R0: Dry-run skeleton** | Package layout, OCSF finding model, ASFF ingest, locator v0, `posturanet fix --dry-run` on fixtures | Built |
| **R1: SG contracts** | Flow-log collector, SG contract builder, Z3 synthesis, validation pipeline, PR delivery, CLI + GitHub Action, Claude skill, MCP (read-only tools) | Built |
| **R1.5: PosturaNet check** | Contract check where teams already work: `PosturaNet contract` check run on PRs (FR-29, US-4 for one repo), Action `check` mode, offline source check, Claude Code hook, Cursor rule, MCP `check_change` source mode (US-7) | Built |
| **R1.6: Attribute fixes** | `config_attribute` fix type: catalog rows covering Security Hub controls across RDS, Aurora, DocumentDB, Neptune, DynamoDB, KMS, ELB, CloudTrail, ECR, EKS, ElastiCache, DMS, Redshift, SQS, API Gateway, Kinesis, Network Firewall, Athena, EBS, S3, MSK, GuardDuty, Config, Macie, IAM password policy and CodeBuild (FR-48). `posturanet fixes list|show` (FR-49) | Built |
| **R2: Verify + evidence** | Post-merge verification and revert PR (FR-31..FR-33), S3 public-access fix (FR-17, FR-50), IAM least privilege (FR-16, FR-51), the safety benchmark (`bench/`); signed OSCAL evidence (pro) | Built, except evidence (pro) |
| **R3: Outcomes** | Every failed finding gets fix / runbook / exception / none, with coverage (0.3.0) | Built |
| **R4: One issue, many detectors** | One PR per issue across scanners and related controls (FR-28); `findings list|split` over several files; PR comment and Marketplace-ready Action; `contract build --all` for SG, S3 and IAM | On `test` |
| **R5: Detector adapters** | Wiz, Orca, Prisma Cloud JSON ingest (FR-4d, FR-4e). Parsers built; mappings come from the export or the customer, never a built-in table. CSV waits for documented columns or a real export | Parsers built |
| **R6: CloudFormation + SAM** | Locate, fix, contract check and drift on templates; opt-in change-set preview | Merging into `test` |
| **R7: AWS CDK** | Fix PRs to CDK program code (TypeScript, Python), mapped from `aws:cdk:path` metadata; `cdk synth` validation with the CloudFormation checks; contract check through the synthesized template | Merging into `test` |
| **R8: Pulumi** | Fix PRs to Pulumi programs (TypeScript, Python, Go, YAML, AWS Classic), mapped through a `pulumi stack export`; static validation with the CloudFormation checks (`pulumi preview` not run: it needs write-capable credentials); contract check on the program's literals | Merging into `test` |
| **R9: Outcome share** | Opt-in anonymous outcomes (FR-45a) and the "which fixes break prod" dataset | Client on `test`; receiving service not built |
| **R10: Team plan (Pro)** | Org-wide contract gate, event triggers (US-3), license keys, contract history, audit evidence, team view. Lives in the private `pro` branch of the postura repo | First feature not chosen yet |
| **R11: Living contracts (Pro)** | `contract refresh` (new-behavior proposals as contract-update PRs, FR-52), `contract live` (drift of the deployed resource, FR-53), a scheduled workflow (FR-54). Policy packs later | In `posturanet-pro` (private `pro` branch), `living` license flag |

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
- AC1: The MCP tool `check_change` accepts a plan JSON, or checks the Terraform source (optionally only edited files), and returns PASS/BLOCK/UNKNOWN with reasons, for `network`, `s3_public` and `iam` contracts.
- AC3: In Claude Code, a hook checks every `.tf` edit and hands a BLOCK reason back to the agent before it continues.
- AC2: Read-only tools need no confirmation. `open_fix_pr` requires explicit user confirmation.

## 7. Functional requirements

### Ingest
- **FR-1** Accept AWS Security Hub findings in ASFF (file, stdin, or API by finding ID).
- **FR-2** Accept manual input by resource ID or ARN plus control ID.
- **FR-3** Normalize to the internal OCSF-aligned `Finding` model. Reject findings missing required fields, with a clear error.
- **FR-4** Record provenance (raw sha256, schema version).
- **FR-4a** Accept OCSF findings: Prowler `json-ocsf` (and Prowler's ASFF output) and OCSF compliance findings. The control id comes from `compliance.control`, then Prowler's FSBP compliance mapping, then a bundled check → control map. Only FAIL findings are fixable. A file with many findings: use the one fixable finding if there is exactly one; otherwise `posturanet findings list|split`. (Pulled forward from R5.)
- **FR-4b** Accept Terraform scanner reports: Checkov (`-o json`) and Trivy (`config -f json`). Check ids map to controls through a hand-curated table (`ingest/iac_checks.json`), each row checked against the scanner's source; unmapped checks are unsupported. The finding names a Terraform address; locate resolves it against the state (exact address, else the one instance of that type and name), and stops if the resource isn't deployed or the name is ambiguous.
- **FR-4c** Accept Security Hub's own formats. (1) OCSF findings from `get-findings-v2` (`{"Findings": [...]}`) and EventBridge "Findings Imported V2" events; a compliance finding's result is `compliance.status` (only `Fail` is fixable); an exposure finding is not fixed directly, it names the control findings it links. (2) Remediation plans (`GetRemediationsV2`): `posturanet findings pull-plans` reads them read-only with their exposures (`ListExposuresByRemediationV2`) and exposure findings (`GetFindingsV2`). A plan names one resource but no control; the controls come from the exposure findings' related control findings. The attribute-fix controls among them that share a Terraform resource type become one combined fix (`RDS.2+RDS.8`), so one plan is one PR; an evidence fix runs alone; the rest are listed to fix separately. AWS's guidance text and Terraform example are never used to build the change (NFR-4).
- **FR-4d** Accept Wiz, Orca and Prisma Cloud JSON exports, detected from the content: Wiz `issuesV2` GraphQL results (`{"data": {"issues": {"nodes": [...]}}}` or the bare node list), Orca serving-layer alert queries (`{"data": [...]}` with `type: Alert`), Prisma Cloud `GET /alert` and `/v2/alert` (`{"items": [...]}`). Each parser reads only fields the vendor's public API docs or published integration code show (cited in `ingest/vendors.py`): resource id or ARN, account, region, vendor rule id and name. Closed alerts (Wiz RESOLVED/REJECTED, Orca closed/dismissed, Prisma Cloud anything but `open`) are passed. CSV exports are refused with a reason (no vendor documents its CSV columns) and the API request that gives the same findings as JSON, with copy-paste commands in `docs/vendor-exports.md`. A vendor rule maps to a control only when (a) the customer maps it in `.posturanet.yml` (`detectors.<vendor>.rules: {<rule id>: <control>}`, which wins), or (b) the export itself names a supported control id (fix or runbook) under an AWS Foundational Security Best Practices or CIS AWS framework (Wiz `securitySubCategories`, Prisma Cloud `complianceMetadata`; Orca exports carry none). Two different supported controls stop. There is no built-in vendor-rule table.
- **FR-4e** An unmapped vendor rule still ends in an outcome (G4): `none`, with the reason "<vendor> rule <id> has no control mapping; add it under detectors.<vendor>.rules", shown by `findings list` and counted in coverage. Mapped vendor findings work with `findings list|split` and `fix`, and merge with other scanners' reports of the same issue (FR-28).

### Locate
- **FR-5** Find Terraform state using backend config (v1: S3 backend; local state file for tests).
- **FR-6** Map the resource ID to a state address, supporting `module.*`, `count` and `for_each` keys.
- **FR-7** Map the address to source file:line for local modules. Remote modules → UNKNOWN.
- **FR-8** Find the owner from CODEOWNERS, falling back to recent committers.
- **FR-9** Detect drift on the target resource. If it has drifted → stop, report, no PR.
- **FR-10** Return candidates with confidence and reasoning. Never a single unexplained guess.
- **FR-10a** CloudFormation and SAM templates (YAML or JSON, short-form intrinsics included) get the same three evidence-backed fixes as Terraform. The resource's physical id maps to its stack and logical id with read-only `cloudformation:DescribeStackResources` (offline: an export of it), then to the one template file and line that defines that logical id. A resource with no source line (SAM-generated, console-created) or a logical id in several templates without `cloudformation.templates` mapping → UNKNOWN. The edit changes only the target's ingress entries, Block Public Access settings or `Action` lists, in the file's own style. Validation is static: the template parses, only the target changed, re-check and contract invariants pass on the edited template, and (outside a dry run) the target matches the deployed template (`cloudformation:GetTemplate`) and the live resource still matches the template: a security group's ingress, a bucket's Block Public Access flags (`s3:GetBucketPublicAccessBlock`) or a managed policy's actions (`iam:GetPolicyVersion`). A change set needs `cloudformation:CreateChangeSet` (a write), so by default the PR's checks table says it was not run. A customer may opt in (`cloudformation.changeset_preview`, separate role, see NFR-2): PosturaNet then creates an UPDATE change set of the edited template, requires it to show an in-place `Modify` of the target and nothing else (for a security group, its own `SecurityGroupIngress` resources (`GroupId` a `!Ref`/`!GetAtt .GroupId` to it, before or after the edit) may be added, modified, replaced or removed), and deletes it. It never executes it. S3.1 (account Block Public Access) has no CloudFormation resource and stops. `contract check --source` judges contracts on templates too. Checkov and Trivy findings on templates name a file and logical id; the stack is the one `cloudformation.templates` maps that file to, and no mapping (or several stacks) → UNKNOWN.
- **FR-10b** AWS CDK apps in TypeScript and Python get the same three evidence-backed fixes. The physical id maps to stack and logical id as in FR-10a; the synthesized template's `aws:cdk:path` names the construct; the source line is the one L2 constructor call (`SecurityGroup`, `Bucket`, `ManagedPolicy`) in the app whose id is that string literal. L1 `Cfn*` constructs (`CfnSecurityGroup`, `CfnBucket`, `CfnManagedPolicy`, path `…/Id` instead of `…/Id/Resource`) are edited in their literal props: `securityGroupIngress` entries (open ones replaced in the same list), `publicAccessBlockConfiguration` (all four flags true), and the `Action` of each `policyDocument` statement (one-for-one with the template). No path metadata, a computed id, an id used by several constructs, a resource another construct generated, or L1 props that aren't literals → UNKNOWN. The edit changes only literals in the program: ingress rules (`addIngressRule`, `connections.allowFrom` / `allowFromAnyIpv4` with `Peer` literals, or a literal `CfnSecurityGroupIngress` in the group's file, removed when open), after checking the group's file explains the template's ingress exactly: inline CIDR rules match the calls, standalone ingress matches a `CfnSecurityGroupIngress` by construct id, and security-group-peer rules (`addIngressRule(otherSg, …)`, `connections.allowFrom` / `allowTo`) match a literal call by ports and are never edited; rules from other files or computed values stop, `blockPublicAccess` (set to `BLOCK_ALL`; `publicReadAccess: true` stops) and `PolicyStatement` `actions` arrays (after checking they map one-for-one to the synthesized statements). Anything computed stops with UNKNOWN. Validation re-reads the edited source and, outside a dry run, runs `cdk synth --no-lookups` with no AWS credentials in its environment, then the FR-10a checks on the new template; `drift` compares the deployed template with `cloudformation:GetTemplate`. `cdk diff` is not run: it signs in with the CDK CLI's own credentials and bootstrap roles. A dry run needs `cdk.assembly` (a cloud assembly CI already synthesized) and doesn't synthesize. `contract check --source` judges CDK contracts on the synthesized template and points at the construct's line. Attribute fixes (catalog rows, from Security Hub or `CONTROL:id`) on CDK apps locate any L2 construct the same way and add one `addPropertyOverride` / `add_property_override` statement per property on its `node.defaultChild`, right after the construct's statement; a construct not assigned to a variable or an existing override of the same property stops with UNKNOWN, and synth must show the control passes. IaC scanner findings (Checkov, Trivy) on `cdk.out/<stack>.template.json` map through the assembly manifest to the stack and logical id, then run the same fix as a Security Hub finding; a template outside the assembly stops with UNKNOWN.
  - *Java, C# and Go apps are not supported yet (decided 2026-11-18).* Locate and edit don't carry over cleanly: the source reader masks TypeScript and Python strings and comments, finds `new X(this, 'Id', {…})` / `X(self, "Id", k=v)` calls and edits object literals or keyword arguments. Java writes constructs as builder chains (`SecurityGroup.Builder.create(this, "Id").vpc(vpc).build()`, props as chained methods), C# as `new X(this, "Id", new XProps { Vpc = vpc })` with PascalCase members and verbatim `@"…"` strings, and Go as `awsec2.NewSecurityGroup(stack, jsii.String("Id"), &awsec2.SecurityGroupProps{…})` where every literal is wrapped (`jsii.String`, `jsii.Number`) and slices are typed. Each needs its own lexer, call and prop grammar, literal reader and renderer, plus a JVM, .NET or Go toolchain for `cdk synth`; a shallow port would map ids but edit wrongly, which breaks the zero-wrongly-reported-safe bar. Until then a finding on such an app stops UNKNOWN at locate (no TypeScript or Python construct has the id). Revisit when a design partner runs CDK in one of them, Java first (the most common after TypeScript and Python).
- **FR-10c** Pulumi programs in TypeScript, Python, Go and YAML (AWS Classic provider) get the same three evidence-backed fixes. The physical id (or ARN) maps to a URN and resource name offline, from a `pulumi stack export` (`pulumi.stack_export`; required, because PosturaNet never runs the Pulumi CLI); for S3 the target is the bucket's `aws.s3.BucketPublicAccessBlock`. The source line is the one constructor call (`aws.ec2.SecurityGroup`, `aws.s3.BucketPublicAccessBlock`, `aws.iam.Policy`, qualified by its module) whose first argument is that name as a string literal (in Go, `ec2.NewSecurityGroup(ctx, "name", &ec2.SecurityGroupArgs{…})`: the second argument; only `pulumi.String/Int/Bool(…)` of a literal, `…Array{…}`, `&…Args{…}` and a raw-string JSON policy are literals); in a YAML program (`runtime: yaml`), the entry of `resources:` whose key (or literal `name:`) is that name and whose `type` is the matching token. In YAML, `${…}` interpolations (variables, config, other resources), `fn::` calls other than `fn::toJSON` of a literal map, anchors, aliases and tags read as COMPUTED. A resource whose parent is a component is found in the component's code only when exactly one class (Go: function) registers the component's type, the program instantiates it once, and the export has one such component directly under the stack; the source is then the call inside it named by the literal, or the only call of that class if its name is computed. A computed name, several matches, any other resource inside a component, a runtime other than nodejs, python, go or yaml, or a standalone ingress rule in the program that the export doesn't have (or that points at a different group than deployed) → UNKNOWN. Before editing, the literals must give exactly the export's `inputs` (inline `ingress` plus `aws.ec2.SecurityGroupRule` / `aws.vpc.SecurityGroupIngressRule` resources on the group; the four flags; the policy document), and the `inputs` must match the `outputs`, else stop (drift). The edit changes only literals: open ingress entries become one entry per synthesized rule, a rule resource's CIDR list is narrowed when the ports match, the flags become `true`, `Action` lists keep only used actions. A fix that needs a new resource stops. Validation is static: re-read the edited files, only the target's calls changed (`program_scope`), the FR-10a re-check, contract and invariant checks on the edited literals, and drift against the export. `pulumi preview` is not run (state backend sign-in and the stack's own write-capable credentials), and the PR's checks table says so. `contract check --source` judges Pulumi contracts on the working tree's literals; an unresolvable target is UNKNOWN.

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
- **FR-28** Idempotency key `sha256(issue + contract_sha + diff_sha)`, where `issue` is `control@terraform_address`, so the same problem reported by several scanners maps to one PR. An open PR matches on its issue marker, or on its finding id for PRs opened before 0.3.1. Never open duplicate PRs. `findings list|split` take several files and list each control-on-resource once.
- **FR-29** Publish a check run with the summary.
- **FR-30** Never merge. Never apply.

### Living contracts (R11, Pro: `living` license flag)
Shipped in `posturanet-pro`, which adds these commands through the `posturanet.plugins` entry point; the open core has no living-contracts code.

- **FR-52** `posturanet contract refresh <resource>|--all` re-collects each approved contract's evidence with the same read-only collectors, window and confidence rules as `fix` (flow logs for `network`, last-accessed for `iam`, access logs for `s3_public`) and compares it with the contract. A user the contract doesn't cover, placed where `fix` would place it (`must_allow`, or `needs_review`; likely scanners stay out), is a proposed addition. An entry not seen in the whole window is a proposed removal: flagged in the file (`reason` on a network entry or an S3 `must_keep` requester, a `needs_review` line for IAM) and in the PR, and never removed, because a job rarer than the window looks the same. IAM entries a human added (`source: human`) are never flagged. The approved file in the checkout is never edited: the result is printed (`--dry-run`, the default) or delivered as a contract-update PR (`--open-pr`) whose contract goes back to `status: draft`, so approving it is the normal merge with `status: approved` and `approved_by` (US-2 AC3). Confidence below `evidence.min_confidence_for_pr` (or none) → UNKNOWN, no proposal. Draft contracts are skipped. A private S3 bucket with ACLs disabled has no access logs read (as in `fix`), so it is skipped. `--evidence-file` holds one contract's evidence and needs one named contract (FR-12). Exit 3 if any contract is UNKNOWN or a PR couldn't be opened, else 0.
- **FR-53** `posturanet contract live [--resource <r>]` reads each contracted resource as deployed, read-only (`ec2:DescribeSecurityGroups`, `s3:GetBucketPublicAccessBlock`, `s3:GetAccountPublicAccessBlock`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `cloudformation:DescribeStackResources` for CloudFormation and CDK groups, `sts:GetCallerIdentity`; Pulumi group ids come from the offline `pulumi stack export`), and judges it with the same rules as `contract check`: a reopened `0.0.0.0/0`, a removed `must_allow` source, a Block Public Access flag turned off (bucket or account), a public bucket policy, a deployed policy that no longer grants a `must_keep` requester, a `must_remove` wildcard back or a `must_allow` action gone is BLOCK (exit 5) with the contract line. A group with security-group or prefix-list sources (not expanded), a read error, a resource not in the state, a contract for another account and a Pulumi group missing from the stack export are UNKNOWN (exit 3), never PASS.
- **FR-54** A scheduled workflow (shipped with `posturanet-pro`) runs `contract refresh --all --open-pr` then `contract live --github-issues`. One contract-update PR per contract, found again by its issue marker (`contract-refresh@<address>`) and updated in place, unchanged when the proposal is the same (FR-28), and within `delivery.max_open_prs`. One issue per resource whose live state breaks its contract, found again by a marker: a BLOCK opens or updates it, an UNKNOWN only updates an open one, a PASS updates and closes it. The job's exit code is the live check's on BLOCK, else the refresh's.

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
- **FR-38** CLI commands: `init`, `fix`, `fixes list|show`, `contract build|check` (Pro adds `contract refresh|live`), `verify`, `evidence export|verify`, `license status`.
- **FR-39** GitHub Action supporting `workflow_dispatch`, schedule, `repository_dispatch` (pro), `pull_request` (pro gate).
- **FR-40** MCP server (stdio) with tools `explain_finding`, `propose_fix`, `check_change` (read-only) and `open_fix_pr` (needs confirmation).
- **FR-41** Claude skill (`plugin/skills/posturanet/SKILL.md`) describing when and how to call the tools, shipped as a Claude Code plugin (`plugin/`) through the repo's marketplace (`.claude-plugin/marketplace.json`).

### Licensing
- **FR-42** Verify Ed25519-signed license keys offline. Enable only the features listed in the key.
- **FR-43** An expired or invalid key disables Pro features only. Community keeps working and contracts and evidence files stay.
- **FR-44** Show upgrade prompts at most once per run, never blocking a working free feature.
- **FR-45** The optional heartbeat sends only `{lic_id, agent_version}` and can be disabled.
- **FR-45a** Opt-in outcome share (client built; the receiving service isn't built yet, so there is no default endpoint). Off by default. When the customer turns it on, each verify result sends only `{control, fix_type, outcome: held | reverted, evidence_days, agent_version}`: no resource ids, ARNs, IPs, account ids, names, code, state, contracts or finding text. `posturanet outcomes preview` prints exactly what would be sent. `held` is a CONFIRMED verify, `reverted` a REGRESSED one; nothing is sent while a fix is still watching. Sending is best-effort and never changes an exit code. Purpose: learn which fixes break production, across customers.

### Configuration
- **FR-46** `.posturanet.yml` in the repo root (schema in the architecture doc §5), including `detectors.<vendor>.rules` (FR-4d).
- **FR-47** `posturanet init` detects the backend, writes the config, and prints the read-only IAM policy.

## 8. Non-functional requirements

| ID | Requirement |
|---|---|
| **NFR-1 Safety** | Fail closed on any missing context, failed check, unexpected diff scope, timeout or auth error. "Unknown" is a valid result. |
| **NFR-2 No production writes** | The agent must not call any AWS mutating API. This is enforced by an allowlist of read-only API calls in code, plus a test. **One opt-in exception:** with `cloudformation.changeset_preview.enabled` and a separate role, the CloudFormation change-set preview may call `CreateChangeSet`, `DescribeChangeSet` and `DeleteChangeSet` (no resource changes; a control-plane write). It is off by default, always deletes its change set, and `ExecuteChangeSet` is never called: absent from code, checked by a test, and denied in the generated preview policy. |
| **NFR-3 Data residency** | No customer code, state, logs or findings are sent to PosturaNet. Secrets are redacted before any LLM call. The one exception is the opt-in outcome share (FR-45a). |
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
| Living contracts (R11; `posturanet-pro`, `living` flag) | — | ✓ | ✓ | ✓ |
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
- The no-mutating-AWS-calls test passes (NFR-2), the default path makes no change-set call, and `ExecuteChangeSet` appears nowhere in code but the preview policy's Deny.
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
