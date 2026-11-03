"""Find and read remote state for the S3 backend (FR-5).

The state is fetched with `s3:GetObject` through the read-only client, kept in memory only,
and never logged or written to disk (NFR-3).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from posturanet.errors import StageStop
from posturanet.locate.hcl_index import block_span

_TERRAFORM = re.compile(r"^\s*terraform\s*\{", re.MULTILINE)
_S3 = re.compile(r'^\s*backend\s+"s3"\s*\{', re.MULTILINE)
_ATTR = re.compile(
    r'^\s*(bucket|key|region|workspace_key_prefix)\s*=\s*"([^"$]*)"\s*$', re.MULTILINE
)

S3Fetch = Callable[[str, str, str | None], bytes]


@dataclass(frozen=True)
class S3Backend:
    bucket: str
    key: str
    region: str | None


def find_s3_backend(tf_root: Path) -> S3Backend | None:
    for tf in sorted(tf_root.glob("*.tf")):
        text = tf.read_text(encoding="utf-8")
        for t in _TERRAFORM.finditer(text):
            t_open, t_end = block_span(text, t.start())
            m = _S3.search(text, t_open, t_end)
            if not m:
                continue
            b_open, b_end = block_span(text, m.start())
            attrs = dict(_ATTR.findall(text[b_open:b_end]))
            if "bucket" not in attrs or "key" not in attrs:
                raise StageStop(
                    "locate",
                    f'backend "s3" in {tf.name} sets bucket or key outside the file',
                    ["partial backend config (-backend-config) is not supported yet; use --state"],
                )
            return S3Backend(attrs["bucket"], attrs["key"], attrs.get("region"))
    return None


def boto3_s3_fetch(factory: Callable[[str], object]) -> S3Fetch:
    def fetch(bucket: str, key: str, region: str | None) -> bytes:
        client = factory("s3")
        try:
            obj = client.get_object(Bucket=bucket, Key=key)  # type: ignore[attr-defined]
            return bytes(obj["Body"].read())
        except Exception as exc:  # botocore raises many types; all mean "no state"
            raise StageStop(
                "locate",
                f"could not read state s3://{bucket}/{key}",
                ["PosturaNet's role needs s3:GetObject on the state object (read-only)"],
                why=exc.__class__.__name__,
            ) from exc

    return fetch
