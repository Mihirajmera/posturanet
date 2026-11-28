# Security questionnaire answers

Pre-filled answers for vendor security reviews (SIG Lite, CAIQ and in-house questionnaires).
Each answer points at the code or doc that backs it, so a reviewer can check it instead of
taking our word for it. If a question isn't here, ask through [SECURITY.md](../SECURITY.md).

**Short version.** PosturaNet is software you run, not a service you send data to. It runs in
your CI or on a laptop, reads AWS with a read-only role you create, writes only pull requests
(or GitLab merge requests) to your repositories, and never merges, applies or changes
production. Nothing about your environment leaves it, unless you turn on the opt-in outcome
share, which sends five fields and nothing that identifies you.

## 1. Product and deployment

| Question | Answer |
|---|---|
| What is it? | A remediation agent: security finding in, reviewed fix PR out, for AWS with Terraform, CloudFormation (and SAM), CDK and Pulumi. |
| Hosting model | Self-hosted only. A Python package (`pip install posturanet`), a GitHub Action, a Claude Code plugin and an MCP server, all running on infrastructure you control. There is no PosturaNet SaaS that holds your data. |
| Where does it run? | Your CI runner (GitHub Actions, GitLab CI, any runner with Python 3.11+) or a developer machine. |
| Does the vendor operate any infrastructure in the data path? | No. The only vendor-run endpoint is the optional outcome-share receiver (section 3), which is off by default. |
| License | Core: FSL-1.1-ALv2 (source available; each version becomes Apache 2.0 after two years). Paid features: the separate `posturanet-pro` package, unlocked by a signed license key that is checked offline. |
| Source code access | The core is public: you can read and build every line that runs in your environment. |

## 2. Access PosturaNet needs

| Question | Answer |
|---|---|
| AWS permissions | A read-only role you create from `posturanet init > policy.json`. The policy lists each action PosturaNet calls (EC2/Logs Insights for flow logs, IAM last-accessed, S3 configuration reads, CloudTrail, CloudFormation reads, Security Hub `GetFindings`, `sts:GetCallerIdentity`). Add `--s3-bucket` for the state and access-log buckets it should read. |
| Can it change AWS resources? | No. Every AWS call goes through one allowlist (`src/posturanet/aws/readonly.py`); a call not on it raises before it is sent, and a test fails the build if a mutating call appears. |
| Any exception? | One, opt-in and off by default: the CloudFormation change-set preview, with a separate role you create from `posturanet init --changeset-preview`. It may create, describe and delete change sets (no resource changes), always deletes its change set, and has no code path to `ExecuteChangeSet`, which the generated policy also denies. |
| Source-control permissions | GitHub: a token with `contents: write` and `pull-requests: write` (in Actions, the built-in `GITHUB_TOKEN`). GitLab: a project access token with the `api` scope and the Developer role. |
| What does it write to repositories? | Only branches named `posturanet/...` and the PR or merge request on them. It refuses any other branch name in code, never pushes to your base branch, never merges and never approves. |
| Who merges? | A human, through your normal review and branch protection. Auto-merge is not offered. |
| Credentials storage | PosturaNet stores no credentials. It reads tokens from environment variables or your CI's secret store and the AWS role from your normal AWS credential chain. |

## 3. Data handling

| Question | Answer |
|---|---|
| What data does it process? | Findings you give it, your IaC source, Terraform state (read-only), flow logs, S3 access logs, CloudTrail and IAM last-accessed data, all inside your environment. |
| What data leaves your environment? | Nothing by default. No telemetry, no analytics, no crash reports. |
| Opt-in outcome share | If you turn it on, after each `verify` it sends `{control, fix_type, outcome (held or reverted), evidence_days, agent_version}`, for example `{"control": "EC2.19", "fix_type": "sg_ingress", "outcome": "held", "evidence_days": 9, "agent_version": "0.5.3"}`. Never resource ids, ARNs, IPs, account ids, names, code, state, contracts or finding text. The model rejects any other field. `posturanet outcomes preview` prints exactly what would be sent. |
| Where is the shared data kept? | The receiver (`receiver/` in the repo) keeps counters of those five fields and nothing else: no request logs with your IP, no per-customer records. |
| Data at rest | PosturaNet writes run records and contracts inside your repository or working directory. Contracts are committed to your repo by your reviewers, like any other code. |
| Secrets in Terraform state | State is read to locate resources and is never logged, written to PR bodies or sent anywhere. |
| Data retention and deletion | Everything PosturaNet keeps lives in your systems under your retention rules. Deleting the run records and contracts removes it. |
| Data residency | Wherever your CI runs. |
| Customer data in vendor test environments | None. Tests and benchmarks use synthetic data only (RFC 5737/1918 addresses, account `123456789012`). |

## 4. AI and automated decisions

| Question | Answer |
|---|---|
| Does it call an LLM? | No. Fixes come from deterministic code and the Z3 solver; explanations come from templates. An optional customer-owned LLM (FR-19) is planned, not built. |
| If an LLM is added later? | It would be your model, under your account; it would never decide a rule, diff or safety result; its output would be schema-validated and never executed; secrets would be redacted first. |
| Prompt injection | Finding text, code comments, commit messages and tool output are treated as data, never instructions. Scanner text placed in PR bodies is reduced to one plain line (no HTML, comment markers, links, code spans or `@mentions`). |
| Agent guardrails | For AI coding agents, the Claude Code hook checks each infrastructure edit against your contracts, asks before destroy commands (`terraform destroy`, `aws rds delete-db-instance` and others), and the MCP `check_change` tool blocks changes that break a contract. |

## 5. Change safety

| Question | Answer |
|---|---|
| How do you prevent a fix from breaking production? | The fix keeps every source and action the evidence shows in use (the behavior contract); validation runs `terraform plan` (or the tool's own preview) and checks that only the target changed; any missing evidence or failed check stops the run with no PR. After merge, `verify` watches for denied traffic and opens a revert PR on a regression. |
| Is it ever certain? | No. Evidence windows miss rare users. Every PR states the evidence window, confidence, the solver's model scope, residual risk and unknowns. We never call a fix "proven safe". |
| Destructive changes | `contract check` blocks a plan that deletes or replaces a stateful resource (databases, buckets, tables, volumes, keys and others) or turns off deletion protection or backups, unless a human lists the address in `contracts.allow_destroy`. |
| Benchmark | `bench/` publishes 145 synthetic cases with known answers, including the cases PosturaNet gets wrong. |

## 6. Software supply chain

| Question | Answer |
|---|---|
| How are releases published? | From a tag, by GitHub Actions, to PyPI with trusted publishing: no long-lived API token exists. PyPI attaches signed build attestations. |
| SBOM | Each GitHub release carries a CycloneDX SBOM (`posturanet-<version>.cdx.json`) and a signed build-provenance attestation; `gh attestation verify` checks it. See SECURITY.md, "Verifying a release". |
| Dependencies | Declared in `pyproject.toml`; every third-party GitHub Action is pinned to a commit SHA. |
| Code review | Changes land through pull requests with CI (lint, type checks, the full test suite, including the no-mutating-AWS-calls test). |
| Static analysis | `ruff` and `mypy --strict` on every change. |

## 7. Vulnerability management and incidents

| Question | Answer |
|---|---|
| How do I report a vulnerability? | See [SECURITY.md](../SECURITY.md): email with "security" in the subject; reply within 3 business days. |
| Patch policy | Security fixes ship in the latest release on PyPI; upgrade with `pip install -U posturanet`. |
| Incident notification | Because PosturaNet holds no customer data, a vendor-side breach can't expose your data. If a vulnerability affects the software you run, we publish a fixed release and a CHANGELOG security entry. |
| Penetration testing | No third-party penetration test yet. The full source is available for your own review. |

## 8. Company and compliance

| Question | Answer |
|---|---|
| SOC 2 / ISO 27001 | Not yet. PosturaNet is an early-stage company. Because the product is self-hosted and holds no customer data, most controls those reports cover (vendor-side data storage, access to customer environments) don't apply; the controls that do (release integrity, vulnerability handling) are described above and can be checked in the source. |
| Subprocessors | None in the data path. The opt-in outcome receiver is hosted on Vercel and stores only the counters above. |
| Vendor access to your environment | None. PosturaNet staff never receive credentials or access to your AWS accounts or repositories. |
| Insurance, financials | Ask us directly. |

## For reviewers: check it yourself

```bash
pip install posturanet
posturanet init > policy.json                 # every AWS action it can call
posturanet outcomes preview run.json          # exactly what the opt-in share would send
grep -rn "ExecuteChangeSet" src/              # only the preview policy's Deny
pytest -q tests/unit/test_readonly.py         # the no-mutating-AWS-calls test
```
