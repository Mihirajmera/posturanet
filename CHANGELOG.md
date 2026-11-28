# Changelog

All notable changes to PosturaNet. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (docs)
- `integrations/gitlab/posturanet-check.gitlab-ci.yml`: the contract check on GitLab merge requests (plan with a read-only OIDC role, or offline `--source`).
- `CODE_OF_CONDUCT.md`.

### Fixed (docs)
- A broken link to the change-set preview design in the architecture doc, and a line in `bench/README.md` that said no AI agent contender exists (the harness does; no results are published yet).

## [0.5.4] - 2026-11-27

### Added (docs)
- `docs/security-questionnaire.md`: pre-filled answers for vendor security reviews (SIG Lite, CAIQ), each pointing at the code or doc that backs it.

### Added (GitLab merge requests, FR-27a)
- `delivery.provider: gitlab` opens the fix as a merge request on gitlab.com or self-managed GitLab, with the same body, labels, one-MR-per-finding idempotency and open-MR limit. Needs `GITLAB_TOKEN` (api scope). PosturaNet never merges. `verify` and the contract-check status stay GitHub only for now.

### Added (benchmark)
- `python -m bench.agents`: run any coding agent (Claude Code, Codex, Cursor's CLI and others) on the 14 security-group cases under three conditions (finding only, plus flow logs, plus PosturaNet's contract check) and score its fixes with the same ground truth. Agents run on synthetic files with no `AWS_*` variables. No agent results are published yet.

### Added (docs)
- `docs/check-fix-prs.md`: make the PosturaNet contract check a required check on every fix PR, whoever opened it (Wiz, Prowler, Gomboc, coding agents, people), and protect the contracts and `allow_destroy` with CODEOWNERS.

### Added (signed releases and SBOM, NFR-10)
- Each GitHub release now carries a CycloneDX SBOM (`posturanet-<version>.cdx.json`) and signed build-provenance attestations for the wheel, sdist and SBOM. `gh attestation verify <file> --repo Mihirajmera/posturanet` checks them. SECURITY.md says how.

### Changed (post-merge watch sized from the evidence, FR-32)
- `posturanet verify` no longer watches a fixed 72 hours. Security group fixes watch until the least frequent kept source should have come back (daily 72h, weekly 8 days, monthly or rarer 35 days); IAM fixes watch for the longest gap between the last uses of the kept actions (72h to 35 days). The PR says how long and why. `--window` still overrides it. A weekly or monthly job denied after a fix is now caught instead of being reported CONFIRMED after 72h.

### Added (destructive-change rules, FR-55)
- `contract check --plan` and MCP `check_change` with a plan now BLOCK a plan that deletes or replaces a resource holding data (RDS, DynamoDB, S3 buckets, EBS, EFS, KMS keys, VPCs, backup vaults, log groups and more), or turns off deletion protection, skips the final snapshot, sets `force_destroy` or sets backup retention to 0. No contract is needed. A human approves by adding the address (or a glob) to `contracts.allow_destroy` in `.posturanet.yml`; `contracts.destructive: false` turns the rules off.
- The Claude Code plugin adds a PreToolUse hook on Bash: before an agent runs `terraform destroy`, `apply -destroy`, `apply -auto-approve`, `pulumi destroy`, `cdk destroy`, or an AWS CLI delete of stored data, Claude Code asks the user. Plan-only commands (`terraform plan -destroy`) pass.

### Security
- Finding titles and control IDs come from scanners and are untrusted. In PR bodies they are now one plain line: no HTML or comment markers (which could fake a `posturanet:` marker), no Markdown links or code spans, no `@mentions`, at most 200 characters.
- The Action and the CI/release workflows pin every third-party action to a commit SHA, so a moved tag can't change what runs with a customer's `GITHUB_TOKEN` and AWS role, or with the PyPI publish token.

### Fixed (docs)
- The README, PRD, architecture doc, AGENTS.md and the trust diagram described a customer LLM that explains each fix. No LLM is called: rules come from a solver and explanations from templates. An optional customer-owned LLM (FR-19) is now marked planned.

## [0.5.3] - 2026-11-25

### Fixed (docs)
- The architecture doc's sample `.posturanet.yml` used seven keys the config refuses (`aws.regions`, `aws.accounts`, `contracts.require_approved_for_auto`, `validation.required`, `delivery.freeze_windows`, `llm`, `license`). It now validates, and a test keeps it that way.
- No license heartbeat exists: keys are checked offline and send nothing. The PRD, architecture doc, README and trust diagram said otherwise; FR-45 is marked not built.
- PyPI metadata names CloudFormation, CDK and Pulumi, and links the docs.

## [0.5.2] - 2026-11-24

### Changed (docs)
- The outcome share's endpoint is documented as `https://outcomes.posturanet.com/api/outcomes`, PosturaNet's receiver. The client still has no default: a customer sets it.
- Benchmark README: 145 cases, with the CDK and Pulumi families in the summary.
- PRD tiers: signed evidence is in Team (as on the website); the account, contract and monitoring-window limits are marked not enforced yet; unbuilt rows are marked planned.

### Fixed
- `posturanet connect wiz` said "not supported yet" although Wiz, Orca and Prisma Cloud JSON ingest is built (R5). `connect wiz`, `connect orca` and `connect prisma` now print the export steps.

### Changed (project)
- GitHub release notes are taken from this file's section for the tag.
- README names CloudFormation, CDK, Pulumi and the vendor exports, and lists the Team features. PRD release statuses brought up to date.
- Added SECURITY.md, CONTRIBUTING.md, issue templates and a PR template.

## [0.5.1] - 2026-11-24

### Added (outcome-share receiver, FR-45a)
- `receiver/`: the one hosted piece, a standard-library Vercel Python function. `POST /api/outcomes` accepts exactly the five shared fields and keeps counters only (no record, time, headers or IP); `GET` returns held/reverted counts per control and fix type. A test keeps its schema in step with `SharedOutcome`. AGENTS.md records the exception to "no hosted services".

### Changed (listings)
- The Action and plugin descriptions now name CloudFormation, CDK, Pulumi and the 74 settings controls. `docs/marketplace.md` has the steps to list the Action in GitHub Marketplace and the plugin in Anthropic's directory.

### Changed (Athena.1 is retired in Security Hub)
- The Athena.1 catalog row now says Security Hub retired the control on 2024-04-10. The fix stays: Checkov `CKV_AWS_159` and Trivy `AWS-0006` findings still reach it, and the note shows in its PR.

### Changed (docs: audit evidence is built in PosturaNet Pro)
- PRD R2/R10 and architecture 6.9 and 12 describe the evidence records, `evidence keygen | record | export` (Pro) and the free `evidence verify`. No core code changes.

## [0.5.0] - 2026-11-21

### Added (opt-in CloudTrail Lake history for IAM, FR-16b)
- `evidence.cloudtrail_lake` (off by default; needs `event_data_store`, an ARN or id; `lookback_days` defaults to 730): IAM fixes also read the policy's roles' and users' calls from the customer's CloudTrail Lake, so a job last run before last-accessed's ~400 days is kept. History only adds use; an unmapped event source or a group principal leaves the evidence as last-accessed reported it, and a failed query is UNKNOWN.
- New read-only allowlist entries, also in the generated IAM policy: `cloudtrail:StartQuery` and `cloudtrail:GetQueryResults`. They run a query and change no resource. Lake bills per GB scanned.
- IAM evidence files take an optional `cloudtrail_lake: {actions: [{action, last_seen}]}` for offline runs.
- Benchmark: `iam-rare-job-cloudtrail-lake` is correct; `iam-rare-job-outside-tracking` (no Lake) is still an outage.
### Added (Pulumi Java)
- `posturanet fix` and `contract check --source` work on Pulumi Java programs (`runtime: java`), for the same three evidence-backed fixes. The resource is the one `new SecurityGroup("name", SecurityGroupArgs.builder()….build())` call (and `SecurityGroupRule`, `vpc.SecurityGroupIngressRule`, `BucketPublicAccessBlock`, `iam.Policy`) whose name is that string literal. A bare class name counts only in a file that imports it (`import com.pulumi.aws.ec2.SecurityGroup;` or `com.pulumi.aws.ec2.*`). `build/`, `target/` and `test/` directories are skipped.
- Literals are plain `"…"` strings, integers, `true` / `false`, `List.of(…)` / `Arrays.asList(…)`, `Map.of(…)` with string keys, `…Args.builder()` chains of literal setters ending in `.build()` (a list setter such as `.ingress(…)` or `.cidrBlocks(…)` reads its varargs as the list), and `serializeJson(jsonObject(jsonProperty(…), …))` with `jsonArray(…)`, the policy form `pulumi convert` writes. Concatenation, text blocks, variables, config reads, `toBuilder()` and a setter called twice read as COMPUTED and stop with UNKNOWN. No Java parser dependency: the CDK scanner masks Java comments and strings.
- Edits keep the program's style: a new ingress entry is a builder of the entry's own Args type, missing BPA flags are new setters before `.build()` (on their own line when the setters are), and the `jsonArray(…)` Action keeps its layout.
- Components used exactly once work in Java too (`class X extends ComponentResource` with `super("<type>", …)`).
- Benchmark: 10 more Pulumi cases (4 Java fixes, one inside a component; 6 Java traps); 59 in all, 0 wrongly reported safe.

### Added (Pulumi C#)
- `posturanet fix` and `contract check --source` work on Pulumi C# programs (`runtime: dotnet`), for the same three evidence-backed fixes. The resource is the one `new SecurityGroup("name", new() { … })` call (and `SecurityGroupRule`, `Vpc.SecurityGroupIngressRule`, `BucketPublicAccessBlock`, `Iam.Policy`) whose name is that string literal. A bare class name counts only in a file that imports its module (`using Pulumi.Aws.Ec2;`); otherwise it must be qualified (`Aws.Ec2.SecurityGroup`). `bin/` and `obj/` are skipped.
- Literals are plain `"…"` strings, integers, `true` / `false`, `new[] { … }`, `new InputList<…> { … }` and `new List<…> { … }`, `new() { Key = … }` and `new …Args { … }` object initializers, and `JsonSerializer.Serialize(new Dictionary<string, object?> { ["Key"] = … })` (the policy form Pulumi documents; `PolicyDocument` is the policy). Interpolated (`$"…"`), verbatim (`@"…"`) and raw strings, variables, config reads and anonymous objects read as COMPUTED and stop with UNKNOWN. No C# parser dependency: the CDK scanner masks C# comments and strings.
- Edits keep the program's style: a new ingress entry is a copy of the entry's own `new …Args { … }` type, missing BPA flags are added to the object initializer, and the `Action` array keeps its braces and layout. A fix that would empty an inferred `new[] { }` array (it has no element type) stops for a hand edit.
- Components used exactly once work in C# too (`class X : ComponentResource` with `: base("<type>", …)`).
- Benchmark: 10 more Pulumi cases (4 C# fixes, one inside a component; 6 C# traps); 49 in all, 0 wrongly reported safe.

### Added (plugins)
- Plugins: `posturanet` loads `posturanet.plugins` entry points and lets them add commands. A plugin that fails to load prints a warning; every free command keeps working. The core never imports a plugin.
- Two read-only calls join the allowlist and the generated IAM policy, for the live contract check in PosturaNet Pro: `s3:GetAccountPublicAccessBlock` (account-wide Block Public Access, through `s3control`) and `s3:GetBucketPolicy` (the policy text, to check `must_keep` requesters). Neither writes anything.
- S3 contracts: `must_keep` and `needs_review` entries take an optional `reason` (a contract refresh flags a requester it didn't see in the window there, and keeps it).

### Changed (living contracts move to PosturaNet Pro)
- `contract refresh`, the live contract check and the scheduled living workflow (merged to `test` for 0.5.0, never released) now ship in `posturanet-pro` behind the `living` license flag. The open core keeps `contract build` and `contract check --plan|--source`.

### Changed (CSV exports point to the JSON export)
- A Wiz, Orca or Prisma Cloud CSV file is still refused, and the message now names the API request that gives the same findings as JSON (Wiz `issuesV2`, Orca `POST /api/serving-layer/query`, Prisma Cloud `GET /v2/alert?detailed=true`) and links `docs/vendor-exports.md`, a page of copy-paste commands. The commands only read, take credentials from environment variables, and request the fields the parsers use.

### Changed (evidence reads every log the account keeps)
- `evidence.window_days` now defaults to 400 (was 90) and is a look-back cap: the window starts where the logs do. Flow logs: the later of the log group's creation and its retention limit, from `DescribeLogGroups` (already allowlisted); if that call fails, the full window is kept, which can only lower confidence. S3 access logs: the first log object. Hours or days before logs could exist no longer count as gaps, so a longer look-back doesn't lower coverage.
- A job that runs every quarter or less is now seen when the account keeps enough logs. Benchmark: `quarterly-dr-drill-year-of-logs` is correct (the drill is kept and flagged for review) and `s3-partner-every-120-days-year-of-logs` stops on the partner's read. The 90-day versions of both are still outages: no logs, no evidence.
- S3 live evidence past 20,000 access-log objects reads the newest 20,000 and starts the window the day after the oldest one kept, instead of stopping.
- Cost: Logs Insights bills per GB scanned, so a 400-day look-back on a busy VPC scans up to about 4x the data of 90 days. Set `evidence.window_days: 90` to keep the old cost.

### Added (Pulumi components)
- A resource whose stack-export parent is a component (`ComponentResource`) is fixed in the constructor call inside the component's code, when that is unambiguous: exactly one TypeScript or Python class (`super("<type>", …)` / `super().__init__("<type>", …)`) or Go function (`ctx.RegisterComponentResource("<type>", …)`) registers the component's type, the program instantiates it exactly once, and the export has exactly one component of that type, directly under the stack. Inside it, the call is the one whose name is the URN's name as a literal, or else the only call of that class (a name like `` `${name}-sg` `` is accepted there).
- Anything else stops with UNKNOWN and says why: no or several classes register the type, the class is instantiated more than once, the export holds several components of the type, a component nested in another component, several calls of the class with no literal match, or a YAML program.
- Benchmark: 8 more Pulumi cases (a component fix in TypeScript, Python and Go; 5 traps); 39 in all, 0 wrongly reported safe.

### Added (Pulumi Go)
- `posturanet fix` and `contract check --source` work on Pulumi Go programs (`runtime: go`), for the same three evidence-backed fixes. The resource is the one constructor call `ec2.NewSecurityGroup(ctx, "name", &ec2.SecurityGroupArgs{…})` (and `vpc.NewSecurityGroupIngressRule`, `ec2.NewSecurityGroupRule`, `s3.NewBucketPublicAccessBlock`, `iam.NewPolicy`) whose name argument is that string literal. `_test.go` files and `vendor/` are skipped.
- Literals are `pulumi.String("…")`, `pulumi.Int(…)`, `pulumi.Bool(…)` (and their `…Ptr` forms) of a literal, `…Array{…}` slices, `&…Args{Field: …}` structs, and `pulumi.String(`…`)` of a raw string holding a JSON object (the usual policy literal). Variables, `json.Marshal` results, config reads, `pulumi.Sprintf`, positional struct fields and interpreted strings with escapes read as COMPUTED and stop with UNKNOWN. No Go parser dependency: the CDK scanner masks Go comments and strings.
- Edits keep the program's own style: new ingress entries use the struct type the entry already uses, missing BPA flags are added to the struct literal, and the JSON `Action` array keeps its layout. New lines aren't gofmt-aligned; run `gofmt` on the branch if your CI checks it.
- Benchmark: 8 more Pulumi cases (3 Go fixes, 5 Go traps); 31 in all, 0 wrongly reported safe.

### Added (Pulumi YAML)
- `posturanet fix` and `contract check --source` work on Pulumi YAML programs (`runtime: yaml`; resources in `Pulumi.yaml`, or `Main.yaml` under `main:`), for the same three evidence-backed fixes. The resource is the entry of `resources:` whose key (or literal `name:`) is the URN's name and whose `type` is `aws:ec2:SecurityGroup` (with its rule resources), `aws:s3:BucketPublicAccessBlock` or `aws:iam:Policy`, in either token form.
- Literals are strings, integers, booleans, lists, maps and `fn::toJSON` of a literal map. A `${…}` interpolation (a variable, config or another resource), any other `fn::` call, an anchor, alias or tag reads as COMPUTED and stops with UNKNOWN.
- Edits replace only the characters of the values that change (positions from ruamel.yaml's parser), so comments, key order, quotes and indentation stay. Validation, the stack-export checks and the "`pulumi preview` not run" note are unchanged.
- Benchmark: 8 more Pulumi cases (3 YAML fixes, 5 YAML traps); 23 in all, 0 wrongly reported safe.

## [0.4.0] - 2026-11-19

### Added (Wiz, Orca and Prisma Cloud findings, R5)
- `findings list|split` and `fix` read Wiz (`issuesV2` GraphQL results), Orca (serving-layer alert query) and Prisma Cloud (`/alert`, `/v2/alert`) JSON exports, detected from the content. Each parser uses only fields shown in the vendor's public API spec or published integration code, cited in `ingest/vendors.py`.
- A vendor rule maps to a control only from the export itself (an AWS Foundational Security Best Practices or CIS AWS control id PosturaNet supports) or from the customer's `.posturanet.yml`: `detectors.<vendor>.rules: {<vendor rule id>: <control>}`. PosturaNet ships no vendor-rule table.
- An unmapped rule still gets an outcome: `none`, with "<vendor> rule <id> has no control mapping; add it under detectors.<vendor>.rules", counted in coverage. Mapped findings merge with Security Hub, Prowler, Checkov and Trivy reports of the same issue.
- Not yet: CSV exports. None of the three vendors documents its CSV columns, so a CSV file is refused with that reason instead of parsed by guesswork.

### Added (Pulumi)
- `posturanet fix` and `contract check --source` work on Pulumi programs in TypeScript and Python (AWS Classic provider), for the same three evidence-backed fixes. The finding's physical id maps to a URN and resource name offline, through a `pulumi stack export` (`pulumi.stack_export`, required; never commit a real one), then to the one constructor call in the program whose name argument is that literal: `aws.ec2.SecurityGroup` (with its `aws.ec2.SecurityGroupRule` / `aws.vpc.SecurityGroupIngressRule` resources), `aws.s3.BucketPublicAccessBlock`, `aws.iam.Policy`. A computed name, a name used twice, a resource inside a component, or a standalone ingress rule in the code that isn't in the export stops with UNKNOWN.
- The fix edits only literals, in the file's own style: `ingress` entries (one per synthesized rule), a rule resource's `cidrBlocks` / `cidrIpv4`, the four Block Public Access flags, and the `Action` lists of a policy written as an object or `JSON.stringify` / `json.dumps` of one. Before editing, PosturaNet checks the literals give exactly the export's inputs and that the inputs match its outputs (drift). A fix that would need a new resource (no `BucketPublicAccessBlock`, more CIDRs than a `vpc.SecurityGroupIngressRule` holds, other ports than a rule resource has) stops instead.
- Validation is static: the edited files are re-read, only the target's constructor calls change, the CloudFormation re-check, contract and invariant checks pass on the edited literals, and the export shows no drift. `pulumi preview` is not run (it signs in to the state backend and configures the AWS provider with the stack's own, write-capable credentials); the PR's checks table says so. No Pulumi CLI call, no AWS call and no new AWS permissions.
- New config: `iac: pulumi` (auto-detected from `Pulumi.yaml`), `pulumi.program` and `pulumi.stack_export`.
- Benchmark: 15 Pulumi cases (`bench/pulumi.py`): 6 fixes, 9 traps that must stop; 0 wrongly reported safe.
- Not yet: Go, C#, Java and YAML programs, the AWS Native provider, components, `aws.s3.BucketPolicy` statements in contract checks (reported UNKNOWN), attribute fixes and IaC scanner findings on Pulumi programs.

### Added (opt-in outcome share, FR-45a)
- `outcome_share.enabled` (off by default) and `outcome_share.endpoint` (an `https://` URL, required when enabled; there is no default). With it on, `posturanet verify` sends one record per fix that ends CONFIRMED (`held`) or REGRESSED (`reverted`): `{control, fix_type, outcome, evidence_days, agent_version}` and nothing else. Never resource ids, ARNs, IPs, account ids, names, code, state, contracts or finding text.
- `posturanet outcomes preview <run.json>...` prints exactly the records saved `verify --format json` runs would send, and sends nothing.
- Sending is best-effort over HTTPS with a 5 s timeout: any failure is a warning and verify's exit code is unchanged. Not an AWS call; the read-only allowlist and IAM policy are unchanged.
- Verify run records now carry the fix type in `outcome.fix_type`.
- The receiving service isn't built yet.

### Added (AWS CDK)
- L1 `Cfn*` constructs: `CfnSecurityGroup` (open `securityGroupIngress` entries replaced in the same list, open literal `CfnSecurityGroupIngress` removed), `CfnBucket` (`publicAccessBlockConfiguration` with all four flags) and `CfnManagedPolicy` (each literal `policyDocument` statement's `Action` shrunk in place) are fixed when their props are literals; attribute fixes override on the construct itself. A computed prop, a `PolicyDocument` object or an id another construct also uses stops with UNKNOWN. Bench: 3 new L1 fixes; the L1 trap now stops because its props don't explain the template (12 correct, 15 stopped, 0 wrongly reported safe).
- Attribute fixes (attribute-fix catalog rows, from Security Hub or `CONTROL:id`) on CDK apps: PosturaNet adds a property override on the L2 construct's `node.defaultChild`, one statement per property, then checks synth shows the control passes. A construct not assigned to a variable or an existing override of the same property stops with UNKNOWN. Checkov and Trivy findings on `cdk.out/<stack>.template.json` now map through the assembly manifest to the stack and construct and run the same fix as a Security Hub finding. Scanner attribute checks on templates are still unsupported at ingest.
- Security groups whose ingress comes from `connections.allowFrom` / `allowFromAnyIpv4`, from security-group peers (`addIngressRule(otherSg, …)`, `connections.allowFrom` / `allowTo`) or from a literal `CfnSecurityGroupIngress` in the group's file are now fixed: PosturaNet traces each synthesized ingress rule (inline, standalone, peer) to its literal in the file, keeps peer rules untouched, removes open calls and open `CfnSecurityGroupIngress` statements, and writes the synthesized rules as `addIngressRule` calls. Ingress from other files or computed values still stops with UNKNOWN. Bench: 3 new fixable cases and 1 new trap (9 correct, 15 stopped, 0 wrongly reported safe).
- Benchmark: `bench/cdk.py` runs the three fixes on the TypeScript and Python fixture apps and 14 traps that must stop (computed peer, id or action; rules from `connections` or a group peer; `addStatements`; duplicate id; L1 construct; no path metadata; `publicReadAccess`; failed synth; drift). 6 correct, 14 stopped, 0 wrongly reported safe; pinned in `tests/unit/test_bench.py`.
- `posturanet fix` and `contract check --source` work on AWS CDK apps in TypeScript and Python, for the same three evidence-backed fixes. The finding's resource maps to its stack and logical id as for CloudFormation, then through the synthesized template's `aws:cdk:path` to the one L2 construct (`SecurityGroup`, `Bucket`, `ManagedPolicy`) in the app source whose id is that literal. No path metadata, an L1 `Cfn*` construct, or a computed or repeated id stops with UNKNOWN.
- The fix edits the program, not the template, and only literals: `addIngressRule` peers, `blockPublicAccess: BlockPublicAccess.BLOCK_ALL`, `PolicyStatement` `actions`. Before editing, PosturaNet checks the literals explain the synthesized template exactly (every ingress rule, every statement), so rules from `connections.allowFrom` or statements from `addStatements` stop instead of being missed.
- Validation re-reads the edited source and, outside a dry run, runs `cdk synth --no-lookups` with AWS credentials removed from its environment (no AWS calls), then the CloudFormation checks on the new template: only the target changed, the rules match, the contract holds, the control passes, and the target matches the deployed template (`cloudformation:GetTemplate`). `cdk diff` is not run and the PR says so. No new AWS permissions.
- New config: `iac: cdk` (auto-detected from `cdk.json`), `cdk.app`, `cdk.assembly` (a `cdk.out` CI already synthesized; needed for dry runs) and `cdk.binary`.
- Not yet: CDK apps in Java, C# or Go. PRD FR-10b records why: each needs its own source reader and renderer, and a shallow port would edit wrongly. Their findings stop with UNKNOWN at locate.

### Added (opt-in CloudFormation change-set preview)
- `cloudformation.changeset_preview` (off by default, needs its own `role_arn`): outside a dry run, PosturaNet creates an UPDATE change set of the edited template, makes the `changeset` check required, and passes it only when CloudFormation would modify just the target, in place. The change set is always deleted and never executed.
- `posturanet init --changeset-preview` prints the separate policy for that role, with an explicit Deny on `ExecuteChangeSet` and stack writes. The read-only allowlist and `posturanet init` output are unchanged. This is the one opt-in exception to NFR-2.

### Added (CloudFormation and SAM)
- The live security-group drift check compares security-group and prefix-list sources too, not only CIDRs: a peer group or prefix list added or removed outside CloudFormation fails it. A source given as `!Ref`/`!GetAtt` to a resource in the stack is resolved to its id; one that can't be resolved (a parameter, an import, a group name) is named in the check and only CIDRs are compared. No new AWS calls.
- Change-set preview on a security group with standalone `SecurityGroupIngress` resources: the change set may also add, modify, replace or remove the group's own ingress resources (those whose `GroupId` is `!Ref`/`!GetAtt .GroupId` to it). Before, those fixes always failed the `changeset` check. Any other resource, or replacing the group itself, still fails.
- CloudFormation drift reads the live bucket and the live managed policy too, as it already did for security groups: a bucket whose Block Public Access flags or a policy whose actions were changed outside CloudFormation fails the `drift` check, and no PR opens. One read-only call joins the allowlist and the generated IAM policy: `s3:GetBucketPublicAccessBlock`. IAM uses `iam:GetPolicy` and `iam:GetPolicyVersion` (already covered by `iam:Get*`). Inline policies aren't compared live yet.
- `posturanet fix` and `contract check --source` work on CloudFormation and SAM templates (YAML or JSON, `!Ref`/`!GetAtt` short forms included) for the same three evidence-backed fixes: security group ingress, S3 Block Public Access and IAM least privilege. The finding's resource maps to its stack and logical id through `cloudformation:DescribeStackResources`, or offline through `cloudformation.stack_resources` (an export of it), then to the one template that defines it. Anything without a source line, such as a SAM-generated role, stops with UNKNOWN.
- The edit replaces only the target's ingress entries, Block Public Access flags or `Action` lists, in the template's own style; comments and every other line stay as written.
- Validation is static and the PR says so: a change set needs `cloudformation:CreateChangeSet`, a write PosturaNet doesn't hold. Outside a dry run, the target must match the deployed template (`cloudformation:GetTemplate`). `cfn-lint` runs when installed.
- New config: `iac` (`auto`, `terraform`, `cloudformation`) and `cloudformation.stack_resources` / `cloudformation.templates`. Two read-only calls join the allowlist and the generated IAM policy: `cloudformation:DescribeStackResources`, `cloudformation:GetTemplate`.
- `contract build --all` on CloudFormation: a draft contract for every security group, bucket and managed policy in the stack-resources export that a template in the repo defines (`cfn.<stack>.<LogicalId>`). The export is required; SAM-generated resources are left out.
- `posturanet verify` on CloudFormation fixes: the applied and re-check stages read the template the stack runs (`cloudformation:GetTemplate`, already allowlisted), or offline `--state` with `aws cloudformation get-template` output. No new AWS calls. Attribute fixes are verified the same way: each changed property is read from that template (CloudFormation's string spellings such as `"true"` count as applied).
- Attribute fixes on CloudFormation now cover ELB.4, ELB.6 and ELB.12 (application load balancer `LoadBalancerAttributes` Key/Value items, added when missing) and ECS.2 (`AssignPublicIp: DISABLED`). Still unmapped, and UNKNOWN on a template: ELB.14, EC2.8, EC2.25, EKS.8, APIGateway.5, S3.12, S3.17 (no property, or a list of other objects) and the account-scope rows.
- The Claude Code hook and MCP `check_change` check edits to CloudFormation/SAM templates (`.yaml`, `.yml`, `.json`, `.template`). Other YAML and JSON files pass through untouched. A template edit that no longer parses is UNKNOWN, not PASS.
- Attribute fixes work on templates too: 59 catalog rows (RDS, DocumentDB, Neptune, DynamoDB, KMS, ECR, ElastiCache, Redshift, OpenSearch, S3.14 versioning and more) now carry a CloudFormation type and property path, such as `VersioningConfiguration.Status: Enabled` or `DeletionProtection: true`. The edit flips the value in place, appends to a list, or adds the missing property in the template's own style (block YAML, flow, JSON). An intrinsic on the property stops, and rows with no CloudFormation property (ALB attributes, EC2.8, account-scope controls) stop with UNKNOWN. Same static validation as the other template fixes.
- Security groups whose rules live (partly) in separate `AWS::EC2::SecurityGroupIngress` resources (`GroupId: !Ref <group>` or `!GetAtt <group>.GroupId`) are fixed and contract-checked too: an open resource is edited in place or deleted as a clean block, and extra rules are added as copies in the template's style. A `GroupId` PosturaNet can't tie to a resource in the template, or an intrinsic in a rule field, stops with UNKNOWN. Drift and scope checks cover those resources as well.
- For a security group, the `drift` check also reads the live group (`ec2:DescribeSecurityGroups`, already allowlisted) and fails when its CIDR ingress differs from the template's, so a group someone changed outside CloudFormation stops the run instead of getting a PR. Still SKIPPED in a dry run.
- Checkov (`check_type: cloudformation`) and Trivy (`Type: cloudformation`) findings on templates take the same path. The scanner names a template and a logical id; the stack is the one `cloudformation.templates` maps that template to (none, or several, stops with UNKNOWN), and the deployed id comes from the export or `DescribeStackResources(StackName, LogicalResourceId)`. Only the three evidence-backed fixes apply; other checks on templates are listed as unsupported.
- Not yet: S3.1 (no CloudFormation resource).
- An S3.1 finding on a CloudFormation repo stops with UNKNOWN and says why (CloudFormation has no resource type for account-level Block Public Access) and what to do: fix it in the account's Terraform repo (`aws_s3_account_public_access_block`), or have a person turn it on in the S3 console or with `aws s3control put-public-access-block`.
- CloudFormation parameters, conditions and nested stacks. `!Ref <Param>` in a rule, flag or `Action` field reads the deployed stack's value (`cloudformation:DescribeStacks`, new on the allowlist and in the generated IAM policy) or, in a dry run, the parameter's `Default`. NoEcho parameters are never read. `Fn::If` and resource `Condition`s are evaluated only when they follow from known parameters; otherwise the run stops with UNKNOWN. PosturaNet never rewrites a parameterised value: if the fix needs one changed, it stops with UNKNOWN naming the parameter. A resource in a nested stack is found through its parent's `TemplateURL` (or SAM `Location`) when that's a path in the repo; a URL stops with UNKNOWN.

### Added (CloudFormation inline IAM policies)
- IAM least privilege (IAM.1, IAM.21) now also fixes inline policies: `Policies` entries on `AWS::IAM::Role`, `User` and `Group`, `AWS::IAM::Policy` resources attached to them, and the statement documents in a SAM function's `Policies` (found from the `<Function>Role` SAM generates). A finding on the role, user or group picks the one document with the flagged wildcard; the address names it, e.g. `cfn.apps.WorkerRole.worker-data` (SAM: `cfn.<stack>.<Function>.<Function>RolePolicy<n>`), and `contract check --source` reads that document.
- Evidence is the principal's own last-accessed data (`iam:GetRole`/`GetUser`/`GetGroup` plus `GenerateServiceLastAccessedDetails`, both already covered by `iam:Get*` and the allowlist), which covers all its policies and so errs toward keeping actions.
- Stops with UNKNOWN: more than one document with the wildcard, none (SAM policy templates such as `S3ReadPolicy` and managed policy names can't be read as statements), an `AWS::IAM::Policy` shared with other principals, a function with its own `Role`, and intrinsic functions in `Action` or `Resource` (now also for managed policies).

### Added (CloudFormation benchmark)
- `python -m bench` has a CloudFormation and SAM family (`bench/cfn.py`, 21 cases): for each of security group ingress, S3 Block Public Access and IAM least privilege, a fixable template in YAML, in JSON and with short-form intrinsics, plus four traps that must stop the run: an intrinsic in the field the fix edits, a SAM-generated resource and a resource defined in two templates (exit 3, UNKNOWN for the last two), and a deployed stack or live group that differs from the repo (exit 4). Fixes are scored on the edited template. Result: 9 correct, 12 stopped for the stated reason, 0 wrongly reported safe. The runner exits 1 if any CloudFormation case is wrongly reported safe, and `tests/unit/test_bench.py` pins every verdict, exit code and reason.

### Added (contract check on every PR)
- `contract check --github-comment <PR>` and the Action's `comment` input (on by default): one PR comment with the result, posted on BLOCK or UNKNOWN and edited on later pushes, so a fixed PR turns it green. A PR that's green from the start gets no comment. If GitHub refuses the comment (fork PR, no `pull-requests: write`), PosturaNet warns and keeps the check's result and exit code. The Action skips the comment when its pinned `version` predates the flag. The example workflow asks for `pull-requests: write`.
- `contract build --all`: a draft contract for every security group in the Terraform state, each from its own flow logs. A group that stops (no flow logs, say) is listed with its reason and doesn't stop the rest; the exit code is the worst one. `--evidence-file` is refused with `--all`, since it holds one group's flows.
- `action.yml` at the repo root, so the Action can be listed on GitHub Marketplace (`uses: Mihirajmera/posturanet@<tag>`). `action/action.yml` keeps working; a test keeps the two identical.

### Added (contracts everywhere, related controls)
- `contract build --all` now also drafts a contract for every S3 bucket and IAM policy in the state, each from its own evidence; JSON rows name the `resource`.
- A manual target can name its control: `posturanet contract build S3.8:acme-assets`, `posturanet fix IAM.21:arn:aws:iam::123456789012:policy/app --dry-run`.
- Related controls that need the same change on the same resource are one problem: every security group control on a group (the fix narrows every world-open rule, whichever control was reported, so EC2.13 and EC2.19 are one PR and one row), and the bucket-scope S3 controls S3.2, S3.3 and S3.8. IAM.1 and IAM.21 stay separate (they remove different actions), as do attribute fixes. The issue tag is now `sg_ingress@<address>` / `s3_public@<address>` for these.

### Decided (scope)
- PRD v2.0 (pivot): PosturaNet is the remediation layer for every detector, IaC tool and AI coding agent. New goals: every failed finding gets an outcome whatever the scanner or IaC tool, contracts check every change, and an outcome dataset (opt-in). Roadmap R4–R11 replaces the old R3–R5. Requirement IDs are unchanged.
- CloudFormation, CDK and Pulumi are in scope (AGENTS.md §1.4), in that order; not built yet.
- An opt-in outcome share is allowed (AGENTS.md rule 6, PRD FR-45a); not built yet.
- Evidence-backed fix types stay at three.

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
