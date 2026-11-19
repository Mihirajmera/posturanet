"""Pulumi support (TypeScript, Python and YAML programs, AWS Classic provider): map a deployed
resource to its URN through a `pulumi stack export`, edit the literals of its constructor call
in the program, and validate statically. Evidence, contracts, Z3 synthesis and the
CloudFormation re-checks are shared."""

from __future__ import annotations

from posturanet.pulumi.stack import (
    PulumiTarget,
    address,
    is_pulumi,
    load_export,
    locate,
    resolve_address,
    split_address,
)
from posturanet.pulumi.validate import (
    PREVIEW_NOTE,
    iam_diff,
    s3_diff,
    sg_diff,
    validate_iam,
    validate_s3,
    validate_sg,
)

__all__ = [
    "PREVIEW_NOTE",
    "PulumiTarget",
    "address",
    "iam_diff",
    "is_pulumi",
    "load_export",
    "locate",
    "resolve_address",
    "s3_diff",
    "sg_diff",
    "split_address",
    "validate_iam",
    "validate_s3",
    "validate_sg",
]
