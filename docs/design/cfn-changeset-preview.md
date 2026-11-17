# Design: opt-in CloudFormation change-set preview

Status: **approved ("Yes, opt-in as designed") and implemented** in `aws/changeset.py`, `cfn/validate.py`, `posturanet init --changeset-preview`. The IAM `ChangeSetName` condition is applied to `CreateChangeSet` only, since it isn't verified for the other actions; the code only ever deletes `posturanet-*` change sets.
Depends on PR #15 (`cfn/`, FR-10a).

## Why

A CloudFormation fix is validated statically today (architecture §14.4). Every report carries
`changeset: SKIPPED (not required) — needs cloudformation:CreateChangeSet (a write); validated
statically`. A change set is CloudFormation's own preview: it says which resources would change
and whether any would be **replaced**, something static checks can't fully see (for example,
a property CloudFormation treats as replace-on-update). Some customers will accept a narrow,
self-deleting control-plane write to get that answer. Everyone else must see no difference.

## What a change set is (and isn't)

`CreateChangeSet` changes no resource. It stores a pending change set on the stack, which
CloudFormation computes and which shows up in the console and in CloudTrail. Only
`ExecuteChangeSet` applies it. It is still a write to the CloudFormation control plane, so it
can't go through `aws/readonly.py`.

## Design

### 1. Off by default, two separate switches

```yaml
cloudformation:
  changeset_preview:
    enabled: false                     # default
    role_arn: arn:aws:iam::123456789012:role/PosturaNetChangeSetPreview
```

- `enabled: true` without `role_arn` is a config error (unknown or missing → error, as today).
- `role_arn` must differ from `aws.role_arn`. The read-only role stays read-only; the
  preview runs under its own role that the customer creates only if they opt in.
- Dry run / offline → `changeset` stays SKIPPED ("dry run: no change set created").
- No CLI flag that turns it on. The decision lives in the reviewed, committed config file.

### 2. Separate code path, separate allowlist

- `aws/readonly.py` and its `ALLOWLIST` are **not changed**. `iam_policy()` and
  `posturanet init` output stay byte-identical.
- New `aws/changeset.py` with its own `CHANGESET_ACTIONS`:
  `cloudformation:CreateChangeSet`, `cloudformation:DescribeChangeSet`,
  `cloudformation:DeleteChangeSet`, plus two reads it needs: `cloudformation:DescribeStacks`
  (current parameters and capabilities) and `cloudformation:ListChangeSets` (cleanup sweep).
- `ChangeSetClient` exposes **three named methods** (`create`, `describe`, `delete`), not a
  `__getattr__` pass-through. It builds the boto3 call itself, always with
  `ChangeSetType="UPDATE"` and never with `RoleARN`.
- It is built only by `cfn/validate.py` when `changeset_preview.enabled` is true.

### 3. Never `ExecuteChangeSet`

Enforced three ways:
1. **Code.** `ChangeSetClient` has no execute method, and `ExecuteChangeSet` /
   `execute_change_set` are in no allowlist.
2. **Test.** An AST/text scan fails if `execute_change_set` or `ExecuteChangeSet` appears in
   `src/` outside the deny statement below; the existing no-mutating-calls test stays as is.
3. **IAM.** The generated preview policy carries an explicit Deny, which wins over any Allow
   the customer attaches to that role by mistake.

### 4. The opt-in IAM policy (printed by `posturanet init --changeset-preview`)

A second document, never merged into the read-only one:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PosturaNetChangeSetPreview",
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateChangeSet",
        "cloudformation:DeleteChangeSet",
        "cloudformation:DescribeChangeSet",
        "cloudformation:DescribeStacks",
        "cloudformation:ListChangeSets"
      ],
      "Resource": "arn:aws:cloudformation:*:*:stack/*/*",
      "Condition": { "StringLike": { "cloudformation:ChangeSetName": "posturanet-*" } }
    },
    {
      "Sid": "PosturaNetNeverExecutes",
      "Effect": "Deny",
      "Action": [
        "cloudformation:ExecuteChangeSet",
        "cloudformation:CreateStack",
        "cloudformation:UpdateStack",
        "cloudformation:DeleteStack",
        "cloudformation:RollbackStack",
        "cloudformation:ContinueUpdateRollback",
        "iam:PassRole"
      ],
      "Resource": "*"
    }
  ]
}
```

To verify before implementing: which of the Allow actions honour the `ChangeSetName`
condition key (the reads may need their own statement without it). Customers can narrow
`Resource` to their stack ARNs; the docs will show how.

### 5. One run, step by step

1. Skip unless enabled, not a dry run, and the stack exists (locate already found it).
2. `DescribeStacks` → current parameters (all sent as `UsePreviousValue`) and the stack's
   existing capabilities.
3. Sweep: `ListChangeSets` on that stack, delete `posturanet-*` change sets older than 1 hour
   (leftovers from crashed runs).
4. `CreateChangeSet` with `ChangeSetType=UPDATE`, name `posturanet-<diff sha256[:12]>`,
   description "PosturaNet preview. Do not execute; it is deleted after validation.",
   `TemplateBody` = the edited template, `Capabilities` = **only** those the stack already has.
5. Poll `DescribeChangeSet` with backoff until `CREATE_COMPLETE` / `FAILED`, bounded by
   `validation.timeout_s`.
6. **`finally:` `DeleteChangeSet`.** A failed delete is reported in the check detail and the
   run record with the change-set name, and the sweep in step 3 retries it next run.

### 6. Mapping into the `changeset` check (`cfn/validate.py`)

| Situation | result | required |
|---|---|---|
| Not opted in (default) | SKIPPED, today's `CHANGESET_NOTE` | **false** |
| Opted in, dry run / offline | SKIPPED | false |
| Exactly one change: `Modify` on the target logical id, `Replacement: False` | PASS | true |
| `Replacement: True` or `Conditional` | FAIL ("CloudFormation would replace X") | true |
| Any other resource changes, or `Add` / `Remove` | FAIL ("change set touches N resources") | true |
| `FAILED` "didn't contain changes" | FAIL ("the edit changes nothing deployed") | true |
| `InsufficientCapabilities` (fix would need a new capability) | FAIL, next step: human review | true |
| Template > 51,200 bytes (needs `TemplateURL`, an S3 write) | SKIPPED, note says why | false |
| Throttling, timeout, AccessDenied, stack busy (`*_IN_PROGRESS`) | ERROR | true |

Once opted in, the check is required, so ERROR or FAIL stops the run with no PR (golden rule
2, fail closed). The PR's checks table renders it like any other check. `drift` stays as is.

## Doc changes when implemented

- **AGENTS.md** §1.3 rule 1: "except the opt-in change-set preview
  (`docs/design/cfn-changeset-preview.md`): own client, own role, own policy, never executes,
  always deletes." §1.10: add "Touches `aws/changeset.py`? Still no execute path?"
- **PRD**: FR-10a, replace "the PR's checks table says the change set was not run" with the
  opt-in behaviour. NFR-2: "no call that changes a resource; the only control-plane write is
  the opt-in, self-deleting change set". New acceptance criterion: the never-execute test.
- **Architecture**: §5 config (`cloudformation.changeset_preview`), §7.3 (second list and
  second policy, kept apart from the read-only one), §12 (`init --changeset-preview`), §14.4
  validation bullet (the table above).
- **Design system**: wording for the new check details. **CHANGELOG** entry.

## Risks

- **REVIEW_IN_PROGRESS stacks.** `ChangeSetType=CREATE` on a missing stack creates an empty
  stack in `REVIEW_IN_PROGRESS`. Avoided in code (UPDATE only, existing stacks only). IAM has no
  condition key for `ChangeSetType`, so the code is the only guard here; narrowing `Resource`
  to known stack ARNs helps.
- **Someone executes it.** For its short life the change set is visible in the console, and a
  human could click Execute, deploying an unreviewed fix. Mitigated by delete-in-`finally`,
  the description, and the 1-hour sweep; not eliminated.
- **Leftover change sets.** Crash, kill or a failed delete leaves one. The sweep and run
  record cover it; stacks have a change-set limit, so leftovers can block the customer's own
  deploys until removed.
- **Rate limits.** `CreateChangeSet` and `DescribeChangeSet` are throttled per account. One
  change set per run, backoff on describe, throttling → ERROR (no retry storm).
- **Capabilities.** IAM resources need `CAPABILITY_IAM`/`CAPABILITY_NAMED_IAM`; SAM needs
  `CAPABILITY_AUTO_EXPAND`. Passing one is a consent flag. PosturaNet only passes what the
  stack already acknowledged; a fix that needs more stops for a human.
- **Side effects of creation.** CloudFormation Hooks and SAM macros (transforms run Lambda)
  may run on change-set creation; CloudTrail and EventBridge record write events the customer
  may alert on. Documented in the opt-in docs.
- **Stack busy.** A stack mid-update rejects the change set → ERROR, retry later.
- **Repo vs deployed.** Other resources in the repo template may differ from what is
  deployed; the change set then shows extra changes and the check FAILs. That is the honest
  answer, but it will block some fixes `drift` alone would allow.

## Open questions for the human

1. OK to add these write calls (Create/Describe/DeleteChangeSet) behind the opt-in?
2. Separate role (proposed) vs. allowing the same role with the extra policy attached?
