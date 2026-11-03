# PosturaNet sandbox

A small, deliberately open AWS setup for testing PosturaNet end to end: one security group with SSH open to `0.0.0.0/0`, real traffic from known sources, and VPC flow logs. This folder is meant to become its own throwaway GitHub repo, which is the repo PosturaNet opens PRs against.

**Use a separate sandbox AWS account.** This opens port 22 to the internet on purpose. There's no key pair, so nobody can log in, but internet scanners will connect. That noise is part of the test.

## What it creates
| Resource | Why |
|---|---|
| VPC `10.42.0.0/16`, public subnet, internet gateway | Isolated network |
| `module.bastion`: SG with `22/tcp` from `0.0.0.0/0`, t3.micro with no key pair | The finding to fix |
| `aws_instance.client` (t3.nano, optional) | A steady internal source: connects to the bastion every 30 min |
| VPC flow logs (default format) → CloudWatch Logs, 120-day retention | The evidence |
| IAM role `posturanet-sandbox-readonly` | What PosturaNet and `terraform plan` run as |

**Cost:** roughly $5–15 a month, mostly the two instances (often $0 on the free tier). Flow-log ingestion and Logs Insights queries for this traffic volume cost cents. `terraform destroy` removes everything.

## Setup (day 0)
1. Copy this folder into a new private GitHub repo, e.g. `posturanet-sandbox`. In `.github/CODEOWNERS` and `.posturanet.yml`, put your GitHub handle.
2. Apply with **your own admin credentials** (PosturaNet never applies):
   ```bash
   terraform init
   terraform apply -var trusted_principal_arn=arn:aws:iam::<ACCOUNT_ID>:user/<you>
   ```
   Note the outputs: `security_group_id`, `bastion_public_ip`, `posturanet_role_arn`.
3. Add a profile that assumes the read-only role, in `~/.aws/config`:
   ```ini
   [profile posturanet-sandbox]
   role_arn = <posturanet_role_arn output>
   source_profile = default
   region = us-east-1
   ```
   Run every PosturaNet command with `AWS_PROFILE=posturanet-sandbox`, so PosturaNet's calls **and** `terraform plan` both use the read-only role. (`aws.role_arn` in `.posturanet.yml` only applies to PosturaNet's own calls, not to the plan.)
4. Start traffic from your laptop (an external daily source):
   - Windows: `schtasks /Create /SC HOURLY /TN PosturaNetTraffic /TR "powershell -NoProfile -File C:\path\to\traffic\traffic.ps1 -Ip <bastion_public_ip>"`
   - macOS/Linux: `0 9-18 * * * /path/to/traffic/traffic.sh <bastion_public_ip>` in `crontab -e`
5. Optional: copy `traffic/github-actions-traffic.yml.example` to `.github/workflows/traffic.yml` for irregular public sources.
6. Commit and push, including `.terraform.lock.hcl`. Never commit `terraform.tfstate`; it's git-ignored.

## Test plan
| When | Run | Expect |
|---|---|---|
| Day 0 | `posturanet fix <sg-id> --dry-run` | Stops after locate (no evidence in a dry run). Owner from CODEOWNERS. |
| Day 1+ | `posturanet fix <sg-id>` | `evidence` stops: confidence low (under 14 days). Check the sources it lists match your laptop IP and `10.42.1.x`. |
| Day 1+ | `posturanet contract build <sg-id>` | Draft contract in `posturanet/contracts/`. Read it. |
| Day 14+ | `posturanet fix <sg-id>` | Real `terraform plan`, all required checks PASS, `VALIDATED`, risk medium. |
| Day 14+ | `GITHUB_TOKEN=… posturanet fix <sg-id> --open-pr` | A PR in the sandbox repo. Re-run: "PR already open", no duplicate. |
| After merge | `terraform apply`, keep traffic running | Your laptop and the client still connect; the scanners stop. |
| Any time | Edit ingress to drop your IP, `terraform plan -out p && terraform show -json p > plan.json`, `posturanet contract check --plan plan.json` | Exit 5, BLOCK, names your IP. |
| Day 60+ | `posturanet fix <sg-id>` | Confidence high, risk low (if no needs-review sources). |

Use `--format json` and keep the output of every run; those records are the test log.

## What to watch for
- **Scanners.** Port 22 open to the internet collects many one-off public sources. R1 keeps `needs_review` sources in the fix (the safe direction) and labels the PR. Watch how many appear, and whether the rule quota stops the fix. This is the first real-world question the sandbox answers.
- **Plan permissions.** If `terraform plan` fails with AccessDenied under the read-only role, note the action; that's the input for a narrower customer policy.
- **Anything that stops.** STOPPED is a valid answer, but record the reason: each one is either correct fail-closed behavior or a bug.

## Clean up
```bash
terraform destroy -var trusted_principal_arn=<same as apply>
```
and remove the scheduled task or cron entry.
