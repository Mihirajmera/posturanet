"""CloudFormation and SAM support: locate, edit and validate templates for the three
evidence-backed fix types. Evidence, contracts and Z3 synthesis are shared with Terraform."""

from __future__ import annotations

from posturanet.cfn.edit import (
    BUCKET_TYPE,
    POLICY_TYPE,
    SG_TYPE,
    CfnPolicy,
    CfnSecurityGroup,
    parse_policy,
    parse_sg,
    s3_flags,
)
from posturanet.cfn.locate import CfnResource, is_cloudformation, locate, resolve, split_address
from posturanet.cfn.validate import (
    CHANGESET_NOTE,
    iam_diff,
    s3_diff,
    sg_diff,
    validate_iam,
    validate_s3,
    validate_sg,
)

__all__ = [
    "BUCKET_TYPE",
    "CHANGESET_NOTE",
    "POLICY_TYPE",
    "SG_TYPE",
    "CfnPolicy",
    "CfnResource",
    "CfnSecurityGroup",
    "iam_diff",
    "is_cloudformation",
    "locate",
    "parse_policy",
    "parse_sg",
    "resolve",
    "s3_diff",
    "s3_flags",
    "sg_diff",
    "split_address",
    "validate_iam",
    "validate_s3",
    "validate_sg",
]
