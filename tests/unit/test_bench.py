"""The S3 and IAM benchmark families: PosturaNet's verdict on every case is pinned, so a change
that turns a stop into an outage (or an outage into a silent pass) fails here first."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from bench import cfn, iam, pulumi, s3  # noqa: E402

S3_EXPECTED = {
    "s3-private-acls-off": "CORRECT",
    "s3-public-policy-unused": "CORRECT",
    "s3-anonymous-scrapers": "STOPPED",
    "s3-static-website": "STOPPED",
    "s3-cloudfront-no-oac": "STOPPED",
    "s3-cloudfront-oac": "CORRECT",
    "s3-partner-public-policy": "STOPPED",
    "s3-partner-every-120-days": "OUTAGE",  # known miss: invisible in a 90-day log window
    "s3-public-no-logs": "STOPPED",
    "s3-unknown-requester-approved": "CORRECT",
}

IAM_EXPECTED = {
    "iam-ec2-describe": "CORRECT",
    "iam-unused-service": "CORRECT",
    "iam-rare-job-in-window": "CORRECT",
    "iam-rare-job-outside-tracking": "OUTAGE",  # known miss: past IAM's tracking period
    "iam-s3-data-plane": "STOPPED",
    "iam-s3-reviewed": "CORRECT",
    "iam-passrole": "STOPPED",
    "iam-passrole-kept": "CORRECT",
    "iam-no-action-data": "STOPPED",
    "iam-admin-star": "STOPPED",
    "iam-admin-star-reviewed": "CORRECT",
    "iam-young-policy": "STOPPED",
}


def test_s3_verdicts() -> None:
    results = s3.run()
    assert {k: v[0].verdict for k, v in results.items()} == S3_EXPECTED
    assert all(v[0].tool == "PosturaNet" for v in results.values())


def test_iam_verdicts() -> None:
    results = iam.run()
    assert {k: v[0].verdict for k, v in results.items()} == IAM_EXPECTED
    assert not any(v[0].exposed for v in results.values()), "no fix leaves a wildcard"


def test_every_case_has_ground_truth_and_a_known_answer() -> None:
    for case in [*s3.CASES, *iam.CASES]:
        assert case.expect in ("fix", "stop") and case.why
    assert set(S3_EXPECTED) == {c.id for c in s3.CASES}
    assert set(IAM_EXPECTED) == {c.id for c in iam.CASES}


def test_cfn_cases_fix_or_stop_for_the_stated_reason() -> None:
    """CloudFormation: YAML, JSON and short-form templates fix; every trap stops (exit 3 for
    what PosturaNet can't read or map, exit 4 for drift) with its own reason."""
    results = {c.id: cfn.run_case(c) for c in cfn.CASES}
    for case in cfn.CASES:
        result, exit_code = results[case.id]
        assert result.verdict == ("CORRECT" if case.expect == "fix" else "STOPPED"), case.id
        assert exit_code == case.exit_code, (case.id, result.note)
        assert case.says in result.note, (case.id, result.note)
    assert cfn.wrongly_safe({k: [r] for k, (r, _) in results.items()}) == []
    shapes = {(c.family, c.id.rsplit("-", 1)[-1]) for c in cfn.CASES}
    for fam in ("sg", "s3", "iam"):
        assert {(fam, s) for s in ("yaml", "json", "form", "generated", "ambiguous")} <= shapes


def test_pulumi_cases_fix_or_stop_for_the_stated_reason() -> None:
    """Pulumi: TypeScript and Python programs fix; every trap stops with its own reason."""
    results = {c.id: pulumi.run_case(c) for c in pulumi.CASES}
    for case in pulumi.CASES:
        result, exit_code = results[case.id]
        assert result.verdict == ("CORRECT" if case.expect == "fix" else "STOPPED"), case.id
        assert exit_code == case.exit_code, (case.id, result.note)
        assert case.says in result.note, (case.id, result.note)
    assert pulumi.wrongly_safe({k: [r] for k, (r, _) in results.items()}) == []
    for fam in ("sg", "s3", "iam"):
        assert {c.lang for c in pulumi.CASES if c.family == fam and c.expect == "fix"} == {
            "ts",
            "py",
        }
