"""AWS CDK support (TypeScript and Python apps): locate the construct behind a deployed
resource, edit its literal values in the program source, and validate through `cdk synth`
with the CloudFormation checks. Evidence, contracts and Z3 synthesis are shared."""

from __future__ import annotations

from posturanet.cdk.app import (
    CdkRunner,
    CdkTarget,
    SubprocessCdk,
    address,
    assembly,
    is_cdk,
    locate,
    resolve,
    split_address,
)
from posturanet.cdk.validate import (
    CDK_DIFF_NOTE,
    iam_diff,
    s3_diff,
    sg_diff,
    validate_iam,
    validate_s3,
    validate_sg,
)

__all__ = [
    "CDK_DIFF_NOTE",
    "CdkRunner",
    "CdkTarget",
    "SubprocessCdk",
    "address",
    "assembly",
    "iam_diff",
    "is_cdk",
    "locate",
    "resolve",
    "s3_diff",
    "sg_diff",
    "split_address",
    "validate_iam",
    "validate_s3",
    "validate_sg",
]
