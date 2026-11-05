# PosturaNet benchmark (v1)

How safe is an automatic fix for an open security group, a public bucket or a wildcard IAM
policy? This benchmark answers that with 35 cases whose right answer is known in advance, and
publishes PosturaNet's misses next to its wins.

| Family | Cases | PosturaNet correct | Stopped (needed / unneeded) | Outage | Fewest outages, any baseline |
|---|---|---|---|---|---|
| Security groups | 13 | 10 | 2 | 1 | 3 |
| S3 public access (S3.8) | 10 | 4 | 3 / 2 | 1 | 3 |
| IAM least privilege (IAM.1, IAM.21) | 12 | 6 | 4 / 1 | 1 | 7 |

"Needed" stops are cases with no safe automatic fix (a public website, a role that passes an
untracked `iam:PassRole`). "Unneeded" stops are safe fixes PosturaNet declined for lack of
evidence: the finding stays open, nothing breaks.

```bash
# from posturanet/
pip install -e ".[dev]"
python -m bench          # writes bench/RESULTS.md and bench/results.json
```

## What it does

Each of the 13 cases in [`cases.py`](cases.py) is a security group open to `0.0.0.0/0`, plus
the **ground truth**, written down before any tool runs:

- **legit** sources that must keep working, including ones the logs never see (a drill that
  runs every 120 days);
- **hostile** sources that must be blocked: internet scanners, and a fresh internet address
  (`192.0.2.250`) probed on every case.

Flow logs are generated from each source's schedule over a 90-day window (or a shorter one when
the case says logs were enabled recently). Each record carries a byte count: legit sessions
8–120 KB per flow, scanners 60–400 bytes, modeled on what SSH/RDP/Postgres sessions and TCP
probes look like. Addresses are RFC 1918 / RFC 5737 only. A case may also list `approved`
sources: a contract the team approved before the run, written into the repo.

Four contenders fix each case:

| Contender | What it does |
|---|---|
| **PosturaNet** | The real pipeline (`run_fix_full`, check mode): ingest, locate, evidence, contract, Z3 fix, validation. |
| **Revoke open rule** | Deletes the rule open to the internet: the shape of a typical automated remediation. |
| **Private ranges only** | Replaces `0.0.0.0/0` with the RFC 1918 ranges: a common hand fix. |
| **Allow all observed** | Allows every source seen in the flow logs as a `/32`: evidence without judgment. |

The baselines are models of an approach, not runs of any vendor's product.

## How it scores

| Verdict | Meaning |
|---|---|
| Correct | Every legit source still works and every hostile source is blocked. |
| Stopped | No change proposed, with a reason. Safe, but the finding stays open. |
| Outage | The fix blocks a legit source. |
| Still exposed | The fix leaves a hostile source allowed. |
| Invalid | The fix can't be applied (over the 60-rule quota). |

It also sums the addresses each fix still allows on the finding's ports: lower is closer to
least privilege.

## Results today

See [RESULTS.md](RESULTS.md) for every case. In short (PosturaNet, unreleased after 0.1.0):

| Contender | Correct | Stopped | Outage | Still exposed | Invalid | Addresses opened |
|---|---|---|---|---|---|---|
| **PosturaNet** | **10** | 2 | 1 | 0 | 0 | 86 |
| Revoke open rule | 1 | 0 | 12 | 0 | 0 | 0 |
| Private ranges only | 10 | 0 | 3 | 0 | 0 | 232.6M |
| Allow all observed | 6 | 0 | 4 | 2 | 1 | 19 |

- **Private ranges only** ties on correct count because no hostile source in these cases is
  internal. It breaks every case with a public legit source and opens 232.6M addresses
  (17.9M internal per fix); PosturaNet opens 86 in total.
- **Allow all observed** lets scanners in, breaks when logs are short or missing, and produces an
  over-quota fix for 70 runners.

### What changed since v0 (and how)

| Case | Before | Now | Fix |
|---|---|---|---|
| `scanner-noise` | Still exposed | Correct | Rare or one-off internet sources go to `not_kept` and out of the fix, listed in the PR. |
| `persistent-scanner` | Still exposed | Correct | Internet sources averaging under 2,000 bytes per flow are `not_kept`. Every other internet source is flagged for review. |
| `ci-fleet-70` | Stopped | Correct | Exact nested-prefix solver when Z3 times out: same optimum, 70 runners in ≤60 rules, never wider than needed. |
| `quarterly-dr-drill-approved` | (new) | Correct | The approved contract remembers the drill; the fix keeps it. |

### Where PosturaNet still misses

| Case | Result | Why | Next step |
|---|---|---|---|
| `quarterly-dr-drill` | Outage | Without an approved contract, a source rarer than the 90-day window is invisible to flow logs. The PR states this as residual risk, but the fix still blocks it. | Ask owners to list rare jobs in the contract before the first fix (`quarterly-dr-drill-approved` shows this works); longer windows when log retention allows; CloudTrail and ticket signals. |
| `logs-10-days`, `no-flow-logs` | Stopped | Too little evidence. Safe, but the finding stays open. | By design: PosturaNet explains how to enable logs and waits. |

| `s3-partner-every-120-days` | Outage | A partner admitted by the public bucket policy reads every 120 days, outside the 90-day log window, so Block Public Access cuts it off. | Owners list rare requesters in the contract; read the policy's named principals; S3 post-merge watch on 403s (verify has `watch_hours: 0` for S3 today). |
| `iam-rare-job-outside-tracking` | Outage | A yearly job last ran 430 days ago, past IAM's ~400-day tracking period; last-accessed reports it as unused. | Owners add rare actions to `must_allow`; CloudTrail Lake history when the account keeps it longer. |
| `s3-anonymous-scrapers`, `s3-public-no-logs`, `iam-admin-star` | Stopped (unneeded) | Logs can't tell a scraper from a customer; no logs means no evidence; `"*"` covers the untracked `iam:PassRole`. | By design: the PR draft contract asks a human, and the `-approved` / `-reviewed` cases show the path to a fix. |

The byte threshold is a heuristic. A scanner that completes full sessions, or a legit client
that only sends tiny flows, will be misplaced; both cases are listed in the PR for a human. The
scanner fix depends on modeled byte counts; real accounts will be noisier.

PosturaNet's release gate is zero wrongly-reported-safe fixes. The three outages above are the
cases to watch: each is a user that leaves no trace in the evidence window. The residual risk
is disclosed in the PR, but a reviewer could still merge a fix that breaks it.

## S3 and IAM families

[`s3.py`](s3.py) and [`iam.py`](iam.py) run the real pipeline (`run_fix`, check mode) on a
generated repo, with evidence built from each case's ground truth the way AWS would report it:
S3 server access logs over 90 days, IAM action-level last-accessed data (no data-plane
actions, no `iam:PassRole`, nothing past ~400 days). Cases marked `-approved` or `-reviewed`
let PosturaNet write its draft contract, then approve it as a reviewer would.

| S3 contender | What it does |
|---|---|
| **Block always** | Turns on Block Public Access: the shape of a scanner's auto-remediation. |
| **Skip websites** | Blocks unless the bucket hosts a website: a common rule-based exception. |

| IAM contender | What it does |
|---|---|
| **Used actions only** | Swaps each wildcard for the tracked actions last-accessed shows as used, with no gates: a policy generated straight from activity data. |
| **Remove wildcard** | Deletes the wildcard and keeps the rest: a common hand fix. |

A fix is an **outage** when it takes away something a legit user needs (S3: a requester that
only gets in through public access; IAM: an action the workload calls). **Still exposed** means
the targeted wildcard is still there. Pinned verdicts are in `tests/unit/test_bench.py`.

## Limits

- Security groups: ingress only, single-port rules, IPv4, SSH/RDP/Postgres.
- S3: one bucket, S3.8 only; requesters are modeled by kind, not by real log lines.
- IAM: one Allow statement per policy, `jsonencode` form; principals are not modeled
  separately (last-accessed is per policy).
- Terraform is the provider-less double from `tests/fakes.py`; plan scope is checked by parsing
  the patched HCL, not by the AWS provider.
- No LLM-based contender yet: one needs a model and a fixed prompt to be reproducible.
- The cases are synthetic. Real accounts have messier traffic; results here are a floor on
  what to check, not a promise.

## Adding a case

Add a `Case` to `CASES` in `cases.py` with its sources (schedule, `legit=True/False`) and run
`python -m bench`. Write the ground truth first, then look at the results. Never edit a case to
change a verdict.
