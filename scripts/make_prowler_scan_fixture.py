"""Build `tests/fixtures/findings/prowler_ocsf_scan.json`: a synthetic Prowler scan.

Five findings, from the single-finding fixture: SSH open (FAIL, fixable), the same check
passing on another group, an expiring certificate (no PosturaNet fix), a public bucket and an
RDS instance without deletion protection (both fixable). Re-run after changing the base file.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

FIX = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "findings"
ACCOUNT, REGION = "123456789012", "us-east-1"


def _variant(
    base: dict[str, Any],
    check: str,
    controls: list[str],
    *,
    status: str = "FAIL",
    severity: str = "High",
    rtype: str,
    name: str,
    arn: str,
) -> dict[str, Any]:
    item = copy.deepcopy(base)
    item["metadata"]["event_code"] = check
    item["unmapped"]["compliance"] = {"AWS-Foundational-Security-Best-Practices": controls}
    item["status_code"], item["severity"] = status, severity
    item["finding_info"]["uid"] = f"prowler-aws-{check}-{ACCOUNT}-{REGION}-{name}"
    item["finding_info"]["name"] = name
    item["finding_info"]["title"] = f"Synthetic {check}"
    item["message"] = item["status_detail"] = f"Synthetic {status} for {name}."
    item["resources"][0].update({"type": rtype, "name": name, "uid": arn})
    return item


def main() -> None:
    base = json.loads((FIX / "prowler_ocsf_sg22.json").read_text("utf-8"))[0]
    sg22 = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
    scan = [
        base,
        _variant(
            base, sg22, ["EC2.13"], status="PASS", severity="High",
            rtype="AwsEc2SecurityGroup", name="sg-0b22aa11",
            arn=f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0b22aa11",
        ),
        _variant(
            base, "acm_certificates_expiration_check", ["ACM.1"], severity="Medium",
            rtype="AwsCertificateManagerCertificate", name="example.test",
            arn=f"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/00000000-0000-0000-0000-000000000001",
        ),
        _variant(
            base, "s3_bucket_level_public_access_block", ["S3.8"], severity="Medium",
            rtype="AwsS3Bucket", name="acme-assets", arn="arn:aws:s3:::acme-assets",
        ),
        _variant(
            base, "rds_instance_deletion_protection", ["RDS.8"], severity="Medium",
            rtype="AwsRdsDbInstance", name="orders",
            arn=f"arn:aws:rds:{REGION}:{ACCOUNT}:db:orders",
        ),
    ]  # fmt: skip
    out = FIX / "prowler_ocsf_scan.json"
    out.write_text(json.dumps(scan, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
