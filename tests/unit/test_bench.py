"""The S3 and IAM benchmark families: PosturaNet's verdict on every case is pinned, so a change
that turns a stop into an outage (or an outage into a silent pass) fails here first."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from bench import iam, s3  # noqa: E402

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
