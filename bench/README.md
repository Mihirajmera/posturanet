# PosturaNet benchmark (v0)

How safe is an automatic fix for an open security group? This benchmark answers that with
cases whose right answer is known in advance, and publishes PosturaNet's misses next to its wins.

```bash
# from posturanet/
pip install -e ".[dev]"
python -m bench          # writes bench/RESULTS.md and bench/results.json
```

## What it does

Each of the 12 cases in [`cases.py`](cases.py) is a security group open to `0.0.0.0/0`, plus
the **ground truth**, written down before any tool runs:

- **legit** sources that must keep working, including ones the logs never see (a drill that
  runs every 120 days);
- **hostile** sources that must be blocked: internet scanners, and a fresh internet address
  (`192.0.2.250`) probed on every case.

Flow logs are generated from each source's schedule over a 90-day window (or a shorter one when
the case says logs were enabled recently). Addresses are RFC 1918 / RFC 5737 only.

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

See [RESULTS.md](RESULTS.md) for every case. In short (PosturaNet 0.1.0):

- **PosturaNet** is correct on 6, stops on 3, and opens 17 addresses in total across its fixes.
- **Revoke** causes an outage on 11 of 12 cases.
- **Private ranges only** is correct on 9: no hostile source in these cases is internal. It
  breaks every case with a public legit source and opens 214.7M addresses (17.9M internal
  addresses per fix).
- **Allow all observed** matches PosturaNet on easy cases but lets scanners in, breaks when logs
  are short or missing, and produces an over-quota fix for 70 runners.

### Where PosturaNet misses (open work)

| Case | Result | Why | Next step |
|---|---|---|---|
| `quarterly-dr-drill` | Outage | A source rarer than the 90-day window is invisible to flow logs. The PR states this as residual risk, but the fix still blocks it. | Longer windows or CloudTrail/ticket signals for known rare jobs; a review prompt listing contract-less ports. |
| `scanner-noise` | Still exposed | Scanner hits seen on one day each are flagged for human review, but the proposed rules still include them. | Leave one-off internet sources out of the fix by default and list them for review instead. |
| `persistent-scanner` | Still exposed | A scanner hitting daily looks like real use in flow logs and is not flagged. | Flag internet sources for review; consider connection shape (bytes, session length) when available. |
| `ci-fleet-70` | Stopped | 70 sources: the Z3 optimizer hits its 30 s limit, so PosturaNet fails closed. Safe, but no fix. | Pre-aggregate sources into supernet candidates before solving. |

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
