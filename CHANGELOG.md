# Changelog

All notable changes to PosturaNet. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
