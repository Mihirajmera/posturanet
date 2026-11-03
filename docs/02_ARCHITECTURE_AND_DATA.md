# PosturaNet: Architecture and Data

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-02 |
| Status | Active. This is the source of truth for *how* PosturaNet is built. |
| Related | [01_PRD.md](01_PRD.md) (what) · [04_DESIGN_SYSTEM.md](04_DESIGN_SYSTEM.md) (output formats) · [../AGENTS.md](../AGENTS.md) (rules for agents) |

> **Core rule:** the LLM may reason. Deterministic code and explicit policy decide what runs. "Unknown" is a valid result. Every failure path fails closed.

---

## 1. System context

```
            ┌──────────────── customer environment ────────────────┐
 Security   │                                                       │
 Hub ──────►│  EventBridge ─► GitHub repository_dispatch            │
            │                         │                             │
 Engineer ─►│  CLI / Claude skill / MCP ──┐     GitHub Actions runner│
            │                             ▼              ▼          │
            │                     ┌──────── posturanet agent ──────┐│
            │   read-only role ──►│ core (OSS) + pro (licensed)    ││
            │   customer LLM ────►│                                ││
            │   (Bedrock / key)   └───────┬───────────────┬────────┘│
            │                             ▼               ▼         │
            │                      GitHub PR/check   evidence files │
            └─────────────────────────────┬───────────────────────────┘
                                          │ license verification is OFFLINE
                                          ▼ (optional heartbeat: lic_id + version)
                              PosturaNet license service (serverless)
```

**Trust boundary:** everything inside the box belongs to the customer. PosturaNet hosts only the license service. No customer data crosses the boundary (NFR-3).

## 2. Pipeline

```
ingest ─► locate ─► evidence ─► contract ─► synthesize ─► validate ─► deliver ─► verify ─► record
  │         │          │           │            │             │           │          │         │
 Finding  Location  Observations Contract     Diff        Validation    PR       Outcome  Evidence
                                                          Report                          (pro)
```
Each stage is a pure function of its inputs plus read-only I/O, and returns either a result or a `StageStop(reason, next_steps)`. A `StageStop` ends the run with **no PR**, and the reason is printed using the design-system format.

| Stage | Module | Input → Output | Stops when |
|---|---|---|---|
| ingest | `posturanet.ingest` | ASFF / manual → `Finding` | Required fields missing, unsupported control |
| locate | `posturanet.locate` | `Finding` + repo + state → `Location` | No match, remote module, drift, ambiguous with low confidence |
| evidence | `posturanet.evidence` | `Location` + window → `Observations` | Confidence `none` (report-only) |
| contract | `posturanet.contracts` | `Observations` (+ approved contract) → `BehaviorContract` | Unapproved rare sources in auto mode |
| synthesize | `posturanet.synth` | contract + current config → `Diff` | UNSAT (no rule set satisfies the contract), quota exceeded |
| validate | `posturanet.validate` | `Diff` → `ValidationReport` | Any required check fails or is INCOMPLETE |
| deliver | `posturanet.deliver` | report + diff → PR / check run | Not authorized, rate limit, freeze window, duplicate |
| verify | `posturanet.verify` | PR + deploy ref → `Outcome` | n/a (sets REGRESSED / UNKNOWN) |
| record | `posturanet.record` (+ pro `evidence_pack`) | `Outcome` → run record / `EvidenceRecord` | n/a |

## 3. Repository layout

```
posturanet/                         # FSL-1.1-ALv2 (this folder; becomes its own public repo at launch)
  AGENTS.md  CLAUDE.md  README.md  CHANGELOG.md  pyproject.toml
  docs/  01_PRD.md  02_ARCHITECTURE_AND_DATA.md  04_DESIGN_SYSTEM.md
  src/posturanet/
    __init__.py  __main__.py
    models/       finding.py  location.py  observations.py  contract.py
                  diff.py  validation.py  safety_contract.py  outcome.py  config.py
    ingest/       asff.py  manual.py
    locate/       backend.py  tfstate.py  hcl_index.py  codeowners.py  drift.py
    evidence/     flowlogs.py  cloudtrail.py  last_accessed.py  s3_access.py  confidence.py  periodicity.py
    contracts/    builder.py  loader.py  store.py
    synth/        sg_z3.py  iam_z3.py  s3_rules.py  hcl_render.py  templates/
    validate/     runner.py  tf.py  plan_scope.py  invariants.py  recheck.py  guardrails.py
    deliver/      github.py  pr_body.py  check_run.py  idempotency.py
    verify/       postmerge.py  revert.py
    record/       run_record.py
    llm/          client.py  redact.py  prompts/        # optional; never required for deterministic paths
    licensing/    verify.py  features.py
    aws/          session.py  readonly.py           # read-only API allowlist (NFR-2)
    output/       console.py  symbols.py            # design-system rendering
    cli/          app.py
    mcp/          server.py
  action/         action.yml  entrypoint.sh
  skills/posturanet/  SKILL.md  plugin.json
  tests/          unit/  integration/  fixtures/
  bench/          cases/  harness.py
posturanet-pro/                     # private, commercial; imports posturanet.*; never imported by core
  src/posturanet_pro/  living/  gate/  triggers/  evidence_pack/  policy/  automerge/  connectors/  slack/
```

**Dependency rule:** `core` must never import `posturanet_pro`. Pro features register through entry points (`posturanet.plugins`) and are loaded only if the license enables them.

## 4. Technology choices

| Concern | Choice | Notes |
|---|---|---|
| Language | Python 3.11+ | Matches the existing backend and reuses its code |
| Packaging | `pyproject.toml` (hatchling), `src/` layout | `pip install posturanet` / `pipx` |
| CLI | Typer + Rich | Rich renders the design-system output and honours `NO_COLOR` |
| Models | Pydantic v2 | JSON Schema export for the contract and evidence formats |
| HCL | python-hcl2 | Parse `.tf`. Line numbers via a regex fallback index. |
| Solver | z3-solver | Synthesis and invariants |
| AWS | boto3 through the `aws/readonly.py` wrapper | Only allowlisted read calls |
| GitHub | REST via httpx | PRs, check runs, contents. Auth uses `GITHUB_TOKEN` in Actions. |
| YAML | ruamel.yaml (round-trip, keeps comments) | Contracts are human-edited |
| Crypto | cryptography (Ed25519) | License keys and evidence signing |
| Templates | Jinja2 | HCL render, PR body |
| Terraform | Customer's `terraform` binary (≥1.5) | `fmt`, `validate`, `plan -out`, `show -json` |
| Lint | tflint, checkov (optional, detected) | Missing tool → INCOMPLETE, unless config marks it optional |
| Tests | pytest, hypothesis (property tests for synthesis), moto (AWS fakes), respx (GitHub fakes) | |
| MCP | Official Python MCP SDK, stdio transport | |

Reuse from `postura-backend` is described in §13. **Don't** pull in FastAPI, Celery, SQLAlchemy or Redis.

## 5. Configuration: `.posturanet.yml`

```yaml
version: 1
aws:
  role_arn: arn:aws:iam::123456789012:role/PosturaNetReadOnly   # optional; else ambient creds
  regions: [us-east-1]
  accounts: [123456789012]
terraform:
  root: infra/                     # working dir(s) with backend config
  backend: s3                      # s3 | local (tests)
  state_path: terraform.tfstate     # local backend only, relative to repo root; --state overrides
  binary: terraform
evidence:
  flow_logs: { mode: logs_insights, log_group: /vpc/flowlogs }   # or { mode: athena, database: ..., table: ..., workgroup: ... }
  window_days: 90
  min_confidence_for_pr: medium     # high | medium   (low/none never open PRs)
contracts:
  dir: posturanet/contracts
  require_approved_for_auto: true   # auto/event mode needs approved contracts
delivery:
  github: { repo: acme/infra, base: main }
  max_open_prs: 5
  freeze_windows: [{ cron: "0 0 * * 5", duration_hours: 72 }]
  labels: [posturanet, security]
validation:
  required: [fmt, validate, plan_scope, invariants, recheck]
  optional: [tflint, checkov]
llm:
  provider: none                    # none | bedrock | anthropic | openai
  model: ""                         # e.g. a Bedrock model id
license:
  key_env: POSTURANET_LICENSE
  heartbeat: true
```
Validated by `models/config.py`. An unknown key is an error, not ignored.

## 6. Data models

All models are Pydantic v2, serialized as JSON (machine) or YAML (human-edited contracts). Schemas are exported to `docs/schemas/*.json` by `posturanet schema export`.

### 6.1 Finding (OCSF-aligned)
```json
{
  "finding_id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.19/finding/abc",
  "source": "securityhub",
  "control_id": "EC2.19",
  "title": "Security groups should not allow unrestricted access to ports with high risk",
  "severity": "HIGH",
  "resource": { "type": "AwsEc2SecurityGroup", "id": "sg-0a91f3c2", "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a91f3c2",
                "account": "123456789012", "region": "us-east-1" },
  "fix_type": "sg_ingress",
  "observed_at": "2026-10-27T08:00:00Z",
  "provenance": { "raw_sha256": "…", "schema": "asff-2018-10-08" }
}
```
`fix_type` ∈ `sg_ingress | s3_public | iam_least_privilege | unsupported`, mapped from `control_id` by `ingest/controls.json` (JSON so the core needs no extra parser at import time).

### 6.2 Location
```json
{ "address": "module.bastion.aws_security_group.this", "file": "infra/modules/bastion/main.tf", "line": 42,
  "module_path": ["bastion"], "state_source": "s3://acme-tf/prod/net.tfstate", "owners": ["@acme/platform"],
  "drift": false, "confidence": "high", "reasoning": ["id matched in state", "module source local: ./modules/bastion"],
  "alternatives": [] }
```
`drift` is `true | false | null`. `null` means "not checked" and must never be read as "no drift". R1 sets it from the state's `ingress` attributes before synthesis (mismatch → stop) and re-checks it against the plan's `before` values during validation. Locate gives `confidence: medium` when no CODEOWNERS rule matches.

### 6.3 Observations
```json
{ "resource_address": "…", "kind": "network", "source": "vpc_flow_logs",
  "window": { "from": "2026-08-01", "to": "2026-10-28", "days": 89, "coverage_ratio": 0.97, "max_gap_hours": 6 },
  "items": [ { "cidr": "10.0.0.0/16", "port": 22, "proto": "tcp", "count": 18204,
               "first_seen": "…", "last_seen": "…", "period": "daily", "hours_histogram": [ … 24 ints … ] } ],
  "confidence": "high" }
```
**Confidence rules (FR-12):**
| Level | Rule |
|---|---|
| high | ≥ 60 days, coverage_ratio ≥ 0.95, max_gap_hours ≤ 24 |
| medium | 14–59 days, coverage_ratio ≥ 0.90 |
| low | < 14 days, or coverage below the medium threshold |
| none | Logs disabled, inaccessible, or no data for the target |

**Periodicity:** `daily` (seen on ≥ 70% of days), `weekly` (a consistent weekday), `monthly` (a consistent day of month), `rare` (≤ 3 distinct days), `one_off` (1 day). `rare` and `one_off` items get `needs_review: true`.

### 6.4 BehaviorContract (YAML in repo: `posturanet/contracts/<sanitized-address>.yaml`)
```yaml
schema: posturanet.contract/v1
resource: module.bastion.aws_security_group.this
account: "123456789012"
region: us-east-1
kind: network
observed:
  source: vpc_flow_logs
  window: { from: 2026-08-01, to: 2026-10-28, days: 89 }
  confidence: high
must_allow:
  - { cidr: 10.0.0.0/16,    port: 22, proto: tcp, period: daily, owner: vpn }
  - { cidr: 203.0.113.7/32, port: 22, proto: tcp, period: "daily@02:00Z", owner: partner-sftp, ref: SEC-412 }
must_deny:
  - { cidr: 0.0.0.0/0, port: 22, proto: tcp }
  - { cidr: "::/0",    port: 22, proto: tcp }
needs_review: []
unknown_risk: "behavior rarer than once per 89 days is not observed"
status: draft            # draft | approved
approved_by: null
approved_at: null
generated_by: posturanet 0.1.0
```
IAM contracts use `must_allow: [{action, resource}]` and `must_deny: [{action_pattern}]`. S3 contracts use `must_allow: [{principal|origin, operation}]`.

**Default `must_deny` invariants** per fix type are defined in `contracts/invariants.yaml`, e.g. SG: no `0.0.0.0/0` or `::/0` on ports 22, 3389, 3306, 5432, 1433, 6379, 9200, 27017.

### 6.5 Diff
```json
{ "files": [ { "path": "infra/modules/bastion/main.tf", "unified_diff": "…" } ],
  "target_address": "module.bastion.aws_security_group.this", "sha256": "…", "generator": "template:sg_ingress@1" }
```

### 6.6 ValidationReport
```json
{ "status": "PASS",   // PASS | FAIL | INCOMPLETE
  "checks": [ { "id": "fmt", "required": true, "result": "pass", "detail": "" },
              { "id": "plan_scope", "required": true, "result": "pass", "detail": "1 to change, 0 to add, 0 to destroy; only target" },
              { "id": "invariants", "required": true, "result": "pass", "detail": "z3: 4/4 hold", "model_scope": "SG+NACL eval for target ENIs" },
              { "id": "recheck", "required": true, "result": "pass", "detail": "EC2.19 would pass on planned config" },
              { "id": "checkov", "required": false, "result": "skipped", "detail": "checkov not installed" } ] }
```
Status is PASS only if every required check passes. Any required check that is `error` or `skipped` → INCOMPLETE (no PR).

### 6.7 SafetyContract (rendered into the PR)
```yaml
finding: securityhub/EC2.19 sg-0a91f3c2
resource: module.bastion.aws_security_group.this  # infra/modules/bastion/main.tf:42
owner: "@acme/platform"
evidence: { source: vpc_flow_logs, window: 89d, confidence: high }
change: "ingress 0.0.0.0/0:22 -> [10.0.0.0/16:22, 203.0.113.7/32:22]"
preconditions: [no drift on target, flow logs coverage >= 95%]
invariants:
  - { id: deny-internet-22,  result: PASS, method: z3 }
  - { id: allow-observed,    result: PASS, method: z3 }
  - { id: plan-scope,        result: PASS, method: terraform-plan }
  - { id: finding-recheck,   result: PASS, method: check:EC2.19 }
disruption: none        # none | possible | restart | replacement
risk: low               # low | medium | high
residual_risk: ["sources active less than once per 89 days may be missed"]
unknowns: []
post_merge: { recheck: true, watch: flowlog_reject_from_must_allow, window: 72h, on_regression: revert_pr }
status: VALIDATED
model_scope: "Z3 models SG and NACL rule evaluation for the target ENIs only. Routing, proxies and app behavior are out of scope."
```

### 6.8 Outcome and state machine
```
PROPOSED → VALIDATED → OPENED → MERGED → APPLIED → CONFIRMED
   │           │          │        │        │
   └► STOPPED  └► FAILED  └► REJECTED       └► REGRESSED → REVERTED
                                    (any) ─► UNKNOWN
```
```json
{ "outcome_id": "out_01J…", "finding_id": "…", "idempotency_key": "…", "state": "CONFIRMED",
  "pr": "acme/infra#412", "merge_sha": "…", "applied_at": "…", "confirmed_at": "…",
  "history": [ { "state": "OPENED", "at": "…" } ] }
```
Outcomes are stored in the repo at `posturanet/outcomes/<yyyy>/<outcome_id>.json` (committed by the PR branch or a bot commit) and in GitHub Actions artifacts. There is no external database.

### 6.9 EvidenceRecord (pro)
```json
{ "schema": "posturanet.evidence/v1", "id": "ev_01J…", "outcome_id": "out_01J…",
  "controls": ["SOC2:CC6.6", "ISO27001:A.8.20", "CIS-AWS-3.0:5.2", "NIST-800-53r5:SC-7"],
  "contract_sha256": "…", "diff_sha256": "…", "pr": "acme/infra#412", "merge_sha": "…",
  "checks": [ { "id": "deny-internet-22", "result": "PASS" } ],
  "verified_at": "2026-10-31T09:00:00Z", "prev_hash": "…", "hash": "…", "signature": "ed25519:…", "key_id": "acme-evidence-2026" }
```
Stored as JSON Lines at `posturanet/evidence/<yyyy>.jsonl`. `hash = sha256(canonical_json(record without hash, signature))`. The signature covers `hash`. Export is to OSCAL `assessment-results`.

### 6.10 RunRecord (NFR-9)
Every run writes `run.json` (as an Actions artifact or to `.posturanet/runs/` locally): agent version, config hash, input hashes, stage results, stop reason, durations, license tier (no key material).

### 6.11 License key
```
key = base64url(payload_json) + "." + base64url(ed25519_signature(payload_json))
payload = { "lic_id": "lic_…", "org": "acme", "tier": "team", "features": ["triggers","gate","living","slack"],
            "accounts_max": 5, "contracts_max": null, "iat": 1761955200, "exp": 1793491200 }
```
The public key is embedded in `licensing/verify.py`. Rotation is supported with a `kid` list.

## 7. Evidence collectors

### 7.1 Flow logs (SG)
1. Resolve the ENIs attached to the SG and their private IPv4/IPv6 addresses: `ec2:DescribeNetworkInterfaces` (filter `group-id`).
2. Query, scoped to those ENIs, the inbound ACCEPT records, and the window. Inbound means `dstAddr` is one of the ENIs' own addresses. `flowDirection` is **not** used: it exists only in custom log formats, and Logs Insights auto-parses only the default format, so filtering on it would silently return no inbound flows and make every rule look unused. A row that can't be parsed stops the run instead of being dropped.
```
fields srcAddr, dstAddr, dstPort, protocol, action, @timestamp
| filter interfaceId in [<enis>] and action = "ACCEPT" and dstAddr in [<eni ips>]
| stats count(*) as n by srcAddr, dstPort, protocol, datefloor(@timestamp, 1h) as hour
```
R1 reads the default flow-log format only. With a custom format the fields aren't parsed, the coverage query finds nothing, and confidence is `none` (fail closed).
3. Aggregate client-side into per-source rows and an hourly histogram, then compute periodicity.
4. Collapse source IPs into CIDRs only through synthesis (§8), never in evidence.
5. Coverage: compare the hours that have any record for the ENIs against the window. Gaps lower the confidence.

Athena mode uses the equivalent SQL with partition pruning (`year/month/day`). Query cost guardrail: refuse if the estimated scan exceeds `evidence.max_scan_gb` (default 50).

### 7.2 CloudTrail + last-accessed (IAM, R3)
- `iam:GenerateServiceLastAccessedDetails` + `GetServiceLastAccessedDetailsWithEntities` → used services.
- CloudTrail (Athena / Lake) → `(eventSource, eventName, resources)` for the principal over the window.
- Optional: Access Analyzer `StartPolicyGeneration` output as an input.

### 7.3 Read-only allowlist (NFR-2)
`aws/readonly.py` wraps boto3 clients and allows only listed operations. Anything else raises `MutatingCallBlocked`. The current allowlist:
`ec2:Describe*`, `logs:StartQuery`, `logs:GetQueryResults`, `logs:DescribeLogGroups`, `athena:StartQueryExecution`, `athena:GetQueryExecution`, `athena:GetQueryResults`, `s3:GetObject` (state bucket, Athena results), `s3:ListBucket`, `iam:Get*`, `iam:List*`, `iam:GenerateServiceLastAccessedDetails`, `iam:SimulatePrincipalPolicy`, `securityhub:GetFindings`, `access-analyzer:Get*`, `access-analyzer:List*`, `sts:GetCallerIdentity`, `sts:AssumeRole`.
(Athena `StartQueryExecution` writes query results to the customer's results bucket. That's documented and is the only side effect.)

**Customer IAM policy** is generated by `posturanet init` from the same allowlist, so the two can't drift apart.

## 8. Synthesis

### 8.1 SG ingress (Z3)
- **Universe:** candidate rules = the observed source IPs/CIDRs × ports, plus aggregated supernets from /32 up to `max_prefix` (default /16 for private ranges, /24 for public), never exceeding the `must_deny` coverage.
- **Booleans:** `use_r` for each candidate.
- **Constraints:**
  - coverage: ∀ a ∈ must_allow: ∨ { use_r : covers(r, a) }
  - deny: ∀ d ∈ must_deny, ∀ r: use_r → ¬overlap_beyond_allowed(r, d)
  - quota: Σ use_r ≤ rules_quota − rules_not_in_scope
- **Objective (Optimize, lexicographic):** minimize total exposed addresses, then the number of rules.
- **Result:** the rule set → `hcl_render.py` rewrites only the target's `ingress` blocks or the `aws_vpc_security_group_ingress_rule` resources, keeping the repo's style (inline vs separate resources, descriptions).
- **UNSAT** → StageStop ("observed traffic needs rules that would violate must_deny: …").

### 8.2 IAM least privilege (R3)
Minimal (action, resource-pattern) set covering the observed pairs, with wildcard limits (`max_wildcards`, never `*:*`). Verification replays every observed call through `SimulatePrincipalPolicy`. SCPs, resource policies and conditions that aren't modeled → `unknowns`.

### 8.3 LLM use (optional)
Allowed only for: (a) choosing between equivalent HCL styles when templates don't match the repo, and (b) writing the plain-English explanation in the PR body. The LLM output is schema-validated, the diff still goes through all validation, and the LLM never sees secrets (`llm/redact.py`) and never chooses rules.

## 9. Validation runner
Runs in a temp copy of the repo. Steps: write the diff → `terraform fmt -check` → `terraform init -backend=…` (read-only credentials) → `validate` → `plan -out` → `show -json` → plan-scope analysis → invariants (Z3 on the planned SG config) → finding re-check (the reused check logic on the planned attributes) → optional tflint/checkov → guardrails. Timeouts per step (default 300 s). A timeout means INCOMPLETE.

**Plan scope rule:** `resource_changes` must contain only the target address (or its rule child resources) with `actions` ⊆ {`update`} or, for separate rule resources, {`create`,`delete`} of rules belonging to the target. Anything else → FAIL.

## 10. Delivery
- Branch: `posturanet/<fix_type>/<short-address>-<idempotency[:8]>`.
- Before creating anything, search open PRs for the label `posturanet` and body marker `<!-- posturanet:key=<idempotency> -->`. If one exists → update it, don't create a new one.
- PR body and check-run text follow [04_DESIGN_SYSTEM.md](04_DESIGN_SYSTEM.md) §6–7.
- Never merge, never approve, never push to the base branch.

## 11. Verification
Triggered by `posturanet verify <pr>` (scheduled workflow after apply) with the merge SHA and the expected attributes:
1. Read the live resource → do its attributes match the plan? If not → UNKNOWN ("not yet applied").
2. Re-run the finding check on live state → pass?
3. Watch window: flow-log REJECT from `must_allow` sources (SG), AccessDenied for the principal (IAM).
4. All good at the end of the window → CONFIRMED. Any regression → REGRESSED, open a revert PR (`git revert` of the merge SHA on a new branch), notify the owners.

## 12. Interfaces (contracts)

### CLI
```
posturanet init
posturanet fix <finding-id|resource-id|asff.json> [--dry-run | --open-pr] [--evidence-file flows.json] [--window 90d] [--format text|json]
posturanet contract build <resource> [--evidence-file flows.json] [--window 90d] [--dry-run]
posturanet contract check --plan tfplan.json          # exit 5 on BLOCK, 3 on UNKNOWN
posturanet contract check --source [--file x.tf]      # offline, from HCL; same exit codes
           [--github-check --sha <commit>]            # publish a "PosturaNet contract" check run
posturanet hook claude-code                           # Claude Code PostToolUse hook (stdin event)
posturanet mcp                                        # read-only MCP server (stdio)
posturanet verify <pr-url>
posturanet evidence export --period 2026Q4 --framework soc2     # pro
posturanet evidence verify
posturanet license status
posturanet schema export
```
**Exit codes:** `0` success (including report-only) · `2` usage/config error · `3` stopped (UNKNOWN / fail-closed, no PR) · `4` validation FAIL · `5` gate BLOCK · `6` license required for the requested feature · `10` internal error.

### MCP tools
| Tool | Input | Output | Side effects |
|---|---|---|---|
| `explain_finding` | finding id / resource | Location + evidence summary | none |
| `propose_fix` | finding id / resource | Diff + SafetyContract + ValidationReport | none |
| `check_change` | plan JSON, or nothing + optional `files` (source mode) | PASS / BLOCK / UNKNOWN + reasons, contract lines | none |
| `open_fix_pr` | proposal id | PR URL | **write. Requires confirmation.** |

### GitHub Action inputs
`command` (fix | verify | gate), `target`, `license`, `config` (path), `model` (none | bedrock | …), `dry-run`.
R1 ships `command: fix | contract-check`, `target`, `open-pr`, `dry-run`, `evidence-file`, `working-directory`, `version`; outputs `result` and `pr-url`.
R1.5 adds `command: check` (runs `terraform plan -lock=false` itself, or takes `plan`), `source-only`, `fail-on-unknown`, `check-run`, `github-token`; output `check-url`.

## 13. Reuse from `postura-backend`
| Source | Target | Change |
|---|---|---|
| `app/aws/discovery/checks*.py`, `registry.py`, `runner.py` | `validate/recheck.py` | Extract pure check functions to run against attribute dicts (planned or live) |
| `app/aws/remediation/ip_safe.py`, `fix_builders.py`, `fix_catalog.py`, `typed_actions.py` | `synth/` | Keep sensitive-port lists and safe-CIDR logic. Output HCL, not API calls. |
| `app/aws/safety/engine.py`, `safety_catalog*.py` | `models/safety_contract.py`, `contracts/invariants.yaml` | Map risk and disruption classes |
| `app/services/formal_verification.py` | `synth/sg_z3.py`, `validate/invariants.py` | Extend from checking to synthesis |
| `app/services/iac_service.py` | `synth/hcl_render.py`, `templates/` | Reuse HCL templates |
| `app/services/rollback_service.py` | `verify/revert.py` | Revert PR instead of API rollback |
| Founder repos `aws-compliance-as-code`, `agent-flight-recorder` | `posturanet-pro/evidence_pack/` | OSCAL mapping, hash chain, signing |

Copy code in. **Don't import from `postura-backend`.** Keep a header comment `# Adapted from postura-backend/<path>` on adapted files.

## 14. Adding a new fix type (checklist)
1. Add the control mapping in `ingest/controls.json`.
2. Add a collector in `evidence/` with confidence rules.
3. Add a contract kind and default invariants.
4. Add synthesis in `synth/` and a template.
5. Add a re-check function in `validate/recheck.py`.
6. Add fixtures plus unit, property and benchmark cases. The wrongly-reported-safe count must stay 0.
7. Update the PRD (FRs) and this doc.

## 15. Testing strategy
| Layer | Tooling | Must cover |
|---|---|---|
| Unit | pytest | Every model, confidence rules, periodicity, idempotency key, license verify, redaction |
| Property | hypothesis | Synthesis: result satisfies the contract; minimality; deny never violated |
| AWS fakes | moto + recorded Logs Insights fixtures | Collectors, read-only allowlist (mutating calls raise) |
| GitHub fakes | respx | PR create/update, duplicate detection, check runs |
| Terraform | fixture repos under `tests/fixtures/tf/*` with local state | Locator, plan scope, render style |
| Integration (nightly) | Real AWS sandbox on credits | End-to-end on a live SG with traffic generators |
| Benchmark | `bench/` | PosturaNet vs a plain agent vs ASR: broken behavior, scope, correctness |

**Release gate:** zero wrongly-reported-safe results across unit, property, integration and benchmark.

## 16. R1 implementation notes
Decisions made while building R1. Change them here first if they need to change.

**Run modes.** `--dry-run` makes no AWS, GitHub or `terraform plan` calls and writes nothing. Evidence comes only from `--evidence-file`, and validation is INCOMPLETE by design (plan not run), so a dry run can never open a PR. The default (`check`) runs everything and writes the draft contract into the repo. `--open-pr` also delivers. MCP tools always run as dry runs.

**Evidence file format** (`--evidence-file`), the same rows Logs Insights returns:
```json
{ "enis": ["eni-…"], "window": { "from": "2026-08-01T00:00:00Z", "to": "2026-10-29T00:00:00Z" },
  "missing_hours": ["2026-09-03T10:00:00Z"],
  "records": [ { "srcAddr": "10.0.4.12", "dstPort": "22", "protocol": "6", "hour": "2026-08-01 09:00:00.000", "n": "12" } ] }
```
Without `missing_hours`, coverage counts only hours that have records (conservative). Logs Insights runs one flow query and one coverage query per 7-day chunk; hitting the 10,000-row cap stops the run rather than using partial data.

**Internal vs public.** Exposure decisions use RFC 1918, 100.64.0.0/10 and fc00::/7 explicitly. Python's `is_private` is not used, because it also covers documentation and other special ranges.

**Synthesis scope.** Only rules open to `0.0.0.0/0` or `::/0` are replaced. A contract source already allowed by a remaining rule is not re-covered. `needs_review` sources are kept (the safe direction) and labeled for the reviewer. `must_deny` entries wider than /8 mean "never contain this network"; narrower ones mean "never overlap". Stops: IPv6 sources that need the open rule, separate rule resources, dynamic or non-literal blocks.

**Invariants.** `allow-observed` is proved with Z3 over 32-bit addresses (no address in a contract source is refused). `deny-internet-<port>` is an exact set check (no rule wider than /8 on that port). Both report `model_scope`: the target group's ingress rules only.

**fmt.** If the target file was not fmt-clean before the change, `fmt` is reported as an optional SKIPPED check, because fmt can't separate our lines from existing ones.

**Plans read only.** `terraform plan` runs with `-lock=false -input=false` in a temp copy. A state lock would be a write to the backend.

**Contract check, two inputs (R1.5).** `gate.check_plan` judges `terraform show -json` output and is exact within `model_scope`. `gate.check_source` judges the HCL in the checkout with the same Z3 allow check and deny set check, offline, for editor and agent hooks. It resolves each contract's address through local `module` blocks to the resource block; remote modules, `dynamic` blocks, non-literal values and separate rule resources are UNKNOWN, never PASS. A group is checked only if it has a contract. Results carry the contract line of each broken rule and the resource's file:line, used for check-run annotations and the `caused by` line.

**Check runs.** One `PosturaNet contract` check run per commit (the PR head SHA, not the merge commit). PASS → `success`, BLOCK → `failure`, UNKNOWN → `neutral` with an explanation. At most 50 annotations. Needs `checks: write`; nothing else is written.

**Agent hook.** `posturanet hook claude-code` reads only `tool_input.file_path` from the event, runs the source check on that file, and answers with `{"decision": "block", "reason": …}` on BLOCK or `additionalContext` on UNKNOWN. It always exits 0, so a PosturaNet error never breaks the agent's session. The repo root is the nearest directory above the file holding `.posturanet.yml`.

**Idempotency.** Key = `sha256(finding_id + contract_sha + diff_sha)`, where `contract_sha` covers only the rules (not counts or dates). The PR body carries the key and a finding marker; an open PR for the same finding is updated (or left alone if the key matches), never duplicated. Before writing, the base branch's copy of each changed file must equal the local original.

