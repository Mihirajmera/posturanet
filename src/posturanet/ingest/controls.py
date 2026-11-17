from __future__ import annotations

import json
from functools import cache
from importlib.resources import files

from posturanet.models import FixType


@cache
def _control_map() -> dict[str, FixType]:
    raw = json.loads(files("posturanet.ingest").joinpath("controls.json").read_text("utf-8"))
    return {k: FixType(v) for k, v in raw.items() if not k.startswith("_")}


def fix_type_for(control_id: str) -> FixType:
    found = _control_map().get(control_id)
    if found is not None:
        return found
    from posturanet.configfix.catalog import fixes_for

    return FixType.CONFIG_ATTRIBUTE if fixes_for(control_id) else FixType.UNSUPPORTED


# Bucket-scope S3 controls: all three set the same Block Public Access flags on the bucket
# (s3fix.CONTROLS; a test keeps the two in step). S3.1 is account-wide, a different resource.
_S3_BUCKET_CONTROLS = frozenset({"S3.2", "S3.3", "S3.8"})


def issue_family(control_id: str) -> str:
    """Controls whose fix is the same change to the same resource share one name, so they get
    one PR and one row: every security group control (the fix narrows every world-open rule in
    the group, whichever control was reported), and the bucket-scope S3 controls. IAM.1 and
    IAM.21 remove different actions, and attribute fixes change different settings, so they
    keep their own control.
    """
    fix_type = fix_type_for(control_id)
    if fix_type is FixType.SG_INGRESS:
        return "sg_ingress"
    if fix_type is FixType.S3_PUBLIC and control_id in _S3_BUCKET_CONTROLS:
        return "s3_public"
    return control_id
