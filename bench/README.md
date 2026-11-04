# PosturaNet benchmark (v0)

How safe is an automatic fix for an open security group? This benchmark answers that with
cases whose right answer is known in advance, and publishes PosturaNet's misses next to its wins.

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

The byte threshold is a heuristic. A scanner that completes full sessions, or a legit client
that only sends tiny flows, will be misplaced; both cases are listed in the PR for a human. The
scanner fix depends on modeled byte counts; real accounts will be noisier.

PosturaNet's release gate is zero wrongly-reported-safe fixes. `quarterly-dr-drill` is the case
to watch: the residual risk is disclosed, but a reviewer could still merge a fix that breaks it.

## Limits of v0

- Security group ingress only, single-port rules, IPv4, SSH/RDP/Postgres.
- Terraform is the provider-less double from `tests/fakes.py`; plan scope is checked by parsing
  the patched HCL, not by the AWS provider.
- No LLM-based contender yet: one needs a model and a fixed prompt to be reproducible.
- The cases are synthetic. Real accounts have messier traffic; results here are a floor on
  what to check, not a promise.

## Adding a case

Add a `Case` to `CASES` in `cases.py` with its sources (schedule, `legit=True/False`) and run
`python -m bench`. Write the ground truth first, then look at the results. Never edit a case to
change a verdict.
