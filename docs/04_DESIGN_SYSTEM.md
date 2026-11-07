# PosturaNet: Design System

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-02 |
| Status | Active. Every user-facing output must follow this. |
| Applies to | CLI output · PR bodies · check runs · contract files · MCP responses · Slack messages · docs site / landing page · PDFs |

PosturaNet is an agent. Its **interface** is text: terminal output, pull requests, check runs and YAML files. This design system treats those as the main UI. The web and brand tokens (§10) are reused from `postura-frontend/tailwind.config.ts`.

---

## 1. Principles
1. **Result first.** The first line says what happened: PR opened, stopped, BLOCK, PASS.
2. **Evidence over adjectives.** "18,204 connections in 89 days," not "heavily used."
3. **Say what you didn't check.** Unknowns and residual risk are always visible, never hidden in a collapsed section.
4. **Calm and plain.** No hype, no emoji clutter, no exclamation marks. Short sentences.
5. **Next step always.** Every stop or failure ends with what the human can do.
6. **Honest scope.** Never "proven safe", "guaranteed", "100%", "zero risk". Use "checked", "holds under the modeled scope", "no regression observed in 72h".
7. **Readable without color.** Meaning is carried by symbols and words. Color only reinforces it (NFR-11).

## 2. Voice and terminology

### 2.1 Words we use
| Use | Avoid |
|---|---|
| fix, change, pull request (PR) | patch bomb, magic fix |
| evidence, observed, window | proof (except for "audit evidence") |
| checked, holds, passes | proven, guaranteed, safe (as a promise) |
| stopped, needs input | failed (for fail-closed stops, which are correct behavior) |
| behavior contract (first mention), contract (after) | policy file, spec |
| confirmed (only for the CONFIRMED state) | done, resolved (ambiguous) |
| PosturaNet | Postura, PN, the bot |

### 2.2 Canonical state names (always uppercase in output)
`PROPOSED` · `VALIDATED` · `OPENED` · `MERGED` · `APPLIED` · `CONFIRMED` · `REJECTED` · `REGRESSED` · `REVERTED` · `STOPPED` · `UNKNOWN`
Check results: `PASS` · `FAIL` · `INCOMPLETE` · `BLOCK` · `SKIPPED`
Confidence: `high` · `medium` · `low` · `none` (lowercase)
Risk: `low` · `medium` · `high`. Disruption: `none` · `possible` · `restart` · `replacement`.

## 3. Symbols
| Meaning | Unicode | ASCII fallback (`--ascii` / non-UTF-8 terminal) | Color token |
|---|---|---|---|
| pass / done | `✓` | `[ok]` | success |
| fail / block | `✗` | `[x]` | critical |
| warning / needs review | `!` | `[!]` | warning |
| unknown / stopped | `?` | `[?]` | muted |
| skipped / not run | `–` | `[-]` | muted |
| info / step | `•` | `-` | primary |
| arrow / next step | `→` | `->` | accent |

No other emoji in CLI or check runs. PR titles may start with `🔒` (one emoji, title only).

## 4. CLI output

### 4.1 Layout rules
- Width: wrap at 100 columns. Labels are left-aligned and padded to 12 characters.
- Sections in order: **header** → **steps** → **result** → **next steps**.
- Header: `PosturaNet <version> · <command> · <target>`.
- One line per pipeline stage, using the stage names from architecture §2.
- Numbers use thousands separators. Durations look like `1m 42s`. Dates are ISO (`2026-10-28`).
- `--format json` prints one JSON object (the run record) and nothing else on stdout. Human logs go to stderr.
- `--quiet` prints only the result line and next steps. `--verbose` adds reasoning lines indented under each stage.
- Respect `NO_COLOR`, `TERM=dumb` and non-TTY (no color, no spinners). `FORCE_COLOR` turns color on for recordings.
- Color (TTY only, §10.3): stage symbols by status, stage names and labels bold, the result word by state (green OPENED/VALIDATED/CONFIRMED, blue DRY RUN/WATCHING, yellow STOPPED, red FAIL/BLOCK/REGRESSED), `! …` notes yellow, diff `+` green and `-` red, next-step arrows blue. Hooks, JSON and check runs never carry color.
- `Unknowns` and `Next` rows follow the label on the same line; continuation rows align under the first.

### 4.2 Example: success (`fix --open-pr`)
```text
PosturaNet 0.1.0 · fix · sg-0a91f3c2

  ✓ ingest      securityhub EC2.19 · port 22 open to 0.0.0.0/0 · HIGH
  ✓ locate      infra/modules/bastion/main.tf:42 · module.bastion.aws_security_group.this · @acme/platform
  ✓ evidence    vpc flow logs · 89 days · confidence high
                  10.0.0.0/16      18,204 conns · daily
                  203.0.113.7/32    1,112 conns · daily at 02:00 UTC  ! external, review owner
  ✓ contract    draft written · posturanet/contracts/module.bastion.aws_security_group.this.yaml
  ✓ fix         0.0.0.0/0:22 → 10.0.0.0/16:22, 203.0.113.7/32:22 (2 rules)
  ✓ validate    6/6 required checks PASS · checkov SKIPPED (not installed)
  ✓ deliver     PR opened → https://github.com/acme/infra/pull/412

Result      OPENED · risk low · disruption none
Unknowns    sources active less than once per 89 days are not observed
Next        → review and merge PR #412 · run `posturanet verify` after apply
```

### 4.3 Example: fail-closed stop
```text
PosturaNet 0.1.0 · fix · sg-0b77e101

  ✓ ingest      securityhub EC2.19 · port 3389 open to 0.0.0.0/0 · HIGH
  ✓ locate      infra/rdp/main.tf:12 · aws_security_group.rdp · @acme/it
  ? evidence    no flow logs found for 2 ENIs on this security group · confidence none

Result      STOPPED · no PR opened (PosturaNet never changes a resource without usage evidence)
Next        → enable VPC flow logs for vpc-0c1… (guide: posturanet.dev/docs/flow-logs)
            → re-run in 14+ days: posturanet fix sg-0b77e101
```

### 4.4 Example: validation FAIL
```text
  ✗ validate    plan_scope FAIL · plan also changes aws_instance.bastion (replace)

Result      STOPPED · validation FAIL · no PR opened
Why         the plan touches resources outside the target; this usually means drift or a shared module
Next        → run `terraform plan` in infra/ and resolve the unrelated change, then re-run
```

### 4.5 Upgrade prompt (FR-44): at most once per run, after Next
```text
Tip         PosturaNet Team checks every Terraform PR against your contracts → posturanet.com/pricing
```

### 4.6 Error messages
Format: **what happened**, then **why** (if known), then **what to do**. Never print a stack trace unless `--verbose` or an internal error (exit 10). On an internal error, print the run-record path and ask the user to file an issue, with no secrets in the record.

## 5. Behavior contract files (YAML)
- File name: the sanitized Terraform address with `[`, `]` and `"` replaced, plus `.yaml`.
- Key order: `schema, resource, account, region, kind, observed, must_allow, must_deny, needs_review, unknown_risk, status, approved_by, approved_at, generated_by`.
- One flow-style mapping per entry (`- { cidr: …, port: …, proto: … }`) so diffs stay one line per rule.
- A comment header (2 lines max): `# Generated by PosturaNet. Review must_allow and needs_review, then merge to approve.`
- Keep human edits and comments on regeneration (round-trip YAML).

## 6. Pull request format

### 6.1 Title
`🔒 PosturaNet: <verb> <what> on <resource-short-name> (<control_id>)`
e.g. `🔒 PosturaNet: restrict SSH ingress on bastion SG (EC2.19)`. Max 72 characters.

### 6.2 Body template (Markdown)
```markdown
<!-- posturanet:key=<idempotency_key> -->
**PosturaNet** found a fix for **<control_id> · <finding title>** and checked it against real usage.

| | |
|---|---|
| Resource | `<address>` · `<file>:<line>` |
| Owner | <owners> |
| Risk / disruption | <risk> / <disruption> |
| Evidence | <source> · <days> days · confidence **<confidence>** |

### What changes
<one or two sentences, plain English>

```diff
<the diff, trimmed to the target>
```

### What's using this resource (observed)
| Source | Port | Connections | Pattern | Kept? |
|---|---|---|---|---|
| 10.0.0.0/16 | 22/tcp | 18,204 | daily | ✓ |
| 203.0.113.7/32 | 22/tcp | 1,112 | daily at 02:00 UTC · needs review | ✓ |

### Checks
| Check | Result | Detail |
|---|---|---|
| fmt / validate | ✓ PASS | |
| plan scope | ✓ PASS | 1 to change, 0 to destroy, only the target |
| contract invariants | ✓ PASS | 4/4 hold · Z3, scope: SG+NACL rules for target ENIs |
| finding re-check | ✓ PASS | EC2.19 passes on the planned config |
| checkov | SKIPPED | not installed |

### Unknowns and residual risk
- <always present; write "None identified" only if the list is truly empty>

### Before you merge
- [ ] Confirm the owners of any **needs review** source.
- [ ] Merge to apply through your normal pipeline. PosturaNet never applies changes.

### After merge
PosturaNet re-checks the finding and watches for blocked traffic from kept sources for **<window>**. If it sees a regression, it opens a revert PR.

<details><summary>Safety contract (machine-readable)</summary>

```yaml
<SafetyContract YAML>
```
</details>

<sub>PosturaNet <version> · run <run_id> · evidence and checks describe the tested conditions and modeled scope; they are not a guarantee of production behavior.</sub>
```

### 6.3 Labels
`posturanet` (always) · `security` · `risk:low|medium|high` · `needs-review` (when any needs-review source exists).

## 7. Check runs
- Name: `PosturaNet contract` (gate) · `PosturaNet fix` (fix PRs).
- Conclusion mapping: PASS → `success`, BLOCK → `failure`, INCOMPLETE/UNKNOWN → `neutral` (with an explanation; never silently green).
- Summary first line: `BLOCK · this change would break 1 contract` or `PASS · 3 contracts checked`.
- On a BLOCK, list each broken line:
```text
✗ module.bastion.aws_security_group.this
  breaks must_allow: 203.0.113.7/32 → 22/tcp (partner-sftp, daily at 02:00 UTC)
  caused by: ingress rule removed in infra/modules/bastion/main.tf:44
  → keep the access, or update the contract in the same PR with owner approval
```

## 8. MCP responses
Return structured JSON first (matching the architecture models) and a `summary` string following the CLI result format (`Result … Next …`). Never return raw state, credentials or full log extracts.

## 9. Slack (Team+)
One message per event. First line = result. Max 5 lines plus a link.
```text
✓ PosturaNet opened PR #412 · restrict SSH on bastion SG (EC2.19) · risk low
  Evidence: 89 days of flow logs · 2 sources kept · 1 needs owner review
  → https://github.com/acme/infra/pull/412
```

## 10. Brand and visual tokens (web, docs, PDFs)

### 10.1 Name and logo use
- Wordmark: **PosturaNet** (capital P, capital N, one word). Never "Postura Net", "POSTURANET" or "Posturanet".
- Tagline: *Fixes cloud security issues without breaking prod.*
- Secondary line: *Evidence-backed remediation for AWS + Terraform.*
- Terminal logo (`output/banner.py`): the logo SVG rasterized to half-block pixels, gradient `#3197F3` → `#0066FF`. Only on bare `posturanet` and `init` (stderr), only at an interactive terminal; never in JSON, pipes, CI, MCP or hooks. `NO_COLOR` → no color; non-UTF-8 → text only; `POSTURANET_NO_BANNER=1` → off.

### 10.2 Color tokens
Dark is the primary theme, matching `postura-frontend/tailwind.config.ts`. Light values are for docs, PDFs and light-mode sites.
| Token | Dark | Light | Use |
|---|---|---|---|
| `shell` (page bg) | `#0B0E0F` | `#FFFFFF` | Background |
| `surface` | `#1A1F1D` | `#F5F7F8` | Cards, code frames |
| `elevated` | `#242B28` | `#ECEFF1` | Popovers, hover |
| `border` | `#2A302E` | `#D9DEE2` | Dividers |
| `border-strong` | `#3A423F` | `#B8C0C6` | Inputs, focus outlines |
| `primary` (text) | `#E8E6E1` | `#14202E` | Body text |
| `muted` | `#919693` | `#5A6878` | Secondary text |
| `accent` | `#4C6EF5` | `#3B5BDB` | The single interactive color: links, buttons, focus |
| `success` | `#2FBF71` | `#1A7F37` | PASS, CONFIRMED |
| `warning` | `#EAB308` | `#B35900` | needs review, INCOMPLETE |
| `critical` | `#E5484D` | `#C62828` | FAIL, BLOCK, REGRESSED |
| `path` (data viz only) | `#8B7CF6` | `#6E5BD8` | Attack-path and graph visuals. Never for buttons. |

Rules: one accent only. Status colors are only for status, never decoration. Text contrast ≥ 4.5:1 (WCAG AA) in both themes.

### 10.3 Terminal color mapping (Rich)
`success` → green · `critical` → red · `warning` → yellow · `muted` → dim · `accent` → blue (links, next-step arrows) · labels in bold. No background colors.

### 10.4 Typography
| Role | Font | Notes |
|---|---|---|
| Sans (UI, docs) | `var(--font-sans)` (Inter or the system UI stack) | Body 16px web / 10.5pt print, line-height 1.5 |
| Mono (code, CLI, contracts) | `var(--font-mono)` (JetBrains Mono / Cascadia Mono / Consolas) | Every resource ID, CIDR, address, path and command |
| Headings | Sans, 600 weight | Sentence case, never all caps except state names |

### 10.5 Spacing and shape
4px base scale (4, 8, 12, 16, 24, 32, 48). Radius 6px for cards and code, 9999px for status pills. Card shadow `inset 0 1px 0 rgba(255,255,255,0.04)` (dark).

### 10.6 Components (web/docs)
- **Status pill:** state name, uppercase, status color at 15% background with the full color as text.
- **Evidence table:** same columns as the PR (§6.2). Numbers right-aligned, monospace for addresses.
- **Terminal block:** `surface` background, mono, ~13px, with a copy button. Shows real CLI output from §4.
- **Contract viewer:** YAML with line numbers. `must_allow` lines get a success left border, `must_deny` critical, `needs_review` warning.
- **Callouts:** info (accent), good (success), caution (warning), stop (critical). Left border 4px.

### 10.7 Motion (web only)
Short and functional: 150–200ms ease-out fades and translates of 4px or less (`fade-in` in the Tailwind config). No motion conveys status on its own. Respect `prefers-reduced-motion`.

## 11. Accessibility checklist
- [ ] Every status has a word and a symbol, not just color.
- [ ] ASCII fallback works (`--ascii`).
- [ ] Contrast ≥ 4.5:1 in both themes.
- [ ] Tables have header rows. Diff blocks are labelled.
- [ ] Links are descriptive ("PR #412", not "here").

## 12. Snapshot tests
Each example in §4, §6 and §7 has a snapshot test in `tests/unit/output/`. A change to an output format must update this doc and the snapshot in the same PR.
