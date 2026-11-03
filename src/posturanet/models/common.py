from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FixType(StrEnum):
    SG_INGRESS = "sg_ingress"
    S3_PUBLIC = "s3_public"
    IAM_LEAST_PRIVILEGE = "iam_least_privilege"
    CONFIG_ATTRIBUTE = "config_attribute"
    UNSUPPORTED = "unsupported"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
