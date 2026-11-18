"""L1 `Cfn*` constructs: props are CloudFormation properties, edited in place when literal."""

from __future__ import annotations

from pathlib import Path

import pytest

from posturanet.cdk import source
from posturanet.errors import StageStop
from posturanet.synth.sg_rules import Rule

ADMIN = Rule("10.0.4.12/32", 22, 22, "tcp")


def _one(tmp_path: Path, name: str, text: str, cid: str, cls: str) -> source.Construct:
    (c,) = source.scan(tmp_path / name, text, cid, cls)
    return c


SG_TS = (
    "const sg = new ec2.CfnSecurityGroup(this, 'Sg', {\n"
    "  groupDescription: 'bastion',\n"
    "  vpcId: vpc.vpcId,\n"
    "  securityGroupIngress: [\n"
    "    { cidrIp: '0.0.0.0/0', ipProtocol: 'tcp', fromPort: 22, toPort: 22, "
    "description: 'SSH' },\n"
    "    { cidrIp: '10.0.0.0/16', ipProtocol: 'tcp', fromPort: 9100, toPort: 9100 },\n"
    "  ],\n"
    "});\n"
)


def test_l1_sg_ts_replaces_the_open_entry_in_its_list(tmp_path: Path) -> None:
    c = _one(tmp_path, "s.ts", SG_TS, "Sg", "CfnSecurityGroup")
    src = source.sg_source(c)
    assert [k.rule for k in src.inline] == [
        Rule("0.0.0.0/0", 22, 22, "tcp"),
        Rule("10.0.0.0/16", 9100, 9100, "tcp"),
    ]
    new = source.render_sg(c, src, [ADMIN])
    assert new == SG_TS.replace(
        "    { cidrIp: '0.0.0.0/0', ipProtocol: 'tcp', fromPort: 22, toPort: 22, "
        "description: 'SSH' },\n"
        "    { cidrIp: '10.0.0.0/16', ipProtocol: 'tcp', fromPort: 9100, toPort: 9100 },\n",
        "    { cidrIp: '10.0.0.0/16', ipProtocol: 'tcp', fromPort: 9100, toPort: 9100 },\n"
        "    { cidrIp: '10.0.4.12/32', ipProtocol: 'tcp', fromPort: 22, toPort: 22, "
        "description: 'SSH' },\n",
    )
    assert source.source_rules(source.rescan(c, new)) == sorted(
        [Rule("10.0.0.0/16", 9100, 9100, "tcp"), ADMIN]
    )


def test_l1_sg_python_keeps_the_property_class_and_removes_l1_ingress(tmp_path: Path) -> None:
    text = (
        'sg = ec2.CfnSecurityGroup(self, "Sg", group_description="b", security_group_ingress=[\n'
        '    ec2.CfnSecurityGroup.IngressProperty(cidr_ip="10.0.0.0/16", ip_protocol="tcp",'
        " from_port=9100, to_port=9100),\n"
        "])\n"
        'ec2.CfnSecurityGroupIngress(self, "Rdp", group_id=sg.attr_group_id, cidr_ip="0.0.0.0/0",'
        ' ip_protocol="tcp", from_port=3389, to_port=3389)\n'
    )
    c = _one(tmp_path, "s.py", text, "Sg", "CfnSecurityGroup")
    src = source.sg_source(c)
    assert len(src.inline) == 1 and len(src.l1) == 1
    new = source.render_sg(c, src, [Rule("10.0.4.12/32", 3389, 3389, "tcp")])
    assert "CfnSecurityGroupIngress" not in new
    assert (
        'ec2.CfnSecurityGroup.IngressProperty(cidr_ip="10.0.4.12/32", ip_protocol="tcp", '
        'from_port=3389, to_port=3389, description="' in new
    )


def test_l1_sg_without_ingress_prop_gets_one(tmp_path: Path) -> None:
    text = "new ec2.CfnSecurityGroup(this, 'Sg', { groupDescription: 'b' });\n"
    c = _one(tmp_path, "s.ts", text, "Sg", "CfnSecurityGroup")
    new = source.render_sg(c, source.sg_source(c), [ADMIN])
    assert new.startswith(
        "new ec2.CfnSecurityGroup(this, 'Sg', { groupDescription: 'b', securityGroupIngress: "
        "[{ cidrIp: '10.0.4.12/32', ipProtocol: 'tcp', fromPort: 22, toPort: 22,"
    )


@pytest.mark.parametrize(
    "entry",
    [
        "{ cidrIp: adminCidr, ipProtocol: 'tcp', fromPort: 22, toPort: 22 }",
        "{ ...base, cidrIp: '0.0.0.0/0' }",
        "{ sourceSecurityGroupId: web.ref, ipProtocol: 'tcp', fromPort: 22, toPort: 22 }",
        "rules.ssh",
    ],
)
def test_l1_sg_entry_that_isnt_a_literal_stops(tmp_path: Path, entry: str) -> None:
    text = f"new ec2.CfnSecurityGroup(this, 'Sg', {{ securityGroupIngress: [{entry}] }});\n"
    c = _one(tmp_path, "s.ts", text, "Sg", "CfnSecurityGroup")
    with pytest.raises(StageStop) as e:
        source.sg_source(c)
    assert e.value.unknown


def test_l1_bucket_adds_or_replaces_the_public_access_block(tmp_path: Path) -> None:
    text = "new s3.CfnBucket(this, 'Assets', {\n  bucketName: 'acme',\n});\n"
    c = _one(tmp_path, "s.ts", text, "Assets", "CfnBucket")
    assert not source.blocks_all(c)
    new, summary = source.render_s3(c)
    assert "  publicAccessBlockConfiguration: { blockPublicAcls: true, blockPublicPolicy: true, " \
        "ignorePublicAcls: true, restrictPublicBuckets: true },\n" in new  # fmt: skip
    assert "added" in summary and source.blocks_all(source.rescan(c, new))
    with pytest.raises(StageStop, match="drifted"):
        source.render_s3(source.rescan(c, new))

    py = (
        's3.CfnBucket(self, "Assets", public_access_block_configuration='
        "s3.CfnBucket.PublicAccessBlockConfigurationProperty(block_public_acls=False))\n"
    )
    c = _one(tmp_path, "s.py", py, "Assets", "CfnBucket")
    new, _ = source.render_s3(c)
    assert new == (
        's3.CfnBucket(self, "Assets", public_access_block_configuration='
        "s3.CfnBucket.PublicAccessBlockConfigurationProperty(block_public_acls=True, "
        "block_public_policy=True, ignore_public_acls=True, restrict_public_buckets=True))\n"
    )
    c = _one(tmp_path, "s.py", py.replace("False", "flag"), "Assets", "CfnBucket")
    with pytest.raises(StageStop):
        source.render_s3(c)


def test_l1_policy_document_actions_are_shrunk_in_place(tmp_path: Path) -> None:
    py = (
        'iam.CfnManagedPolicy(self, "App", policy_document={\n'
        '    "Version": "2012-10-17",\n'
        '    "Statement": [\n'
        '        {"Effect": "Allow", "Action": ["ec2:*", "logs:*"], "Resource": "*"},\n'
        '        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},\n'
        '        {"Effect": "Deny", "NotAction": "iam:*", "Resource": "*"},\n'
        "    ],\n"
        "})\n"
    )
    c = _one(tmp_path, "p.py", py, "App", "CfnManagedPolicy")
    sts = source.statements(c)
    assert [s.actions for s in sts] == [["ec2:*", "logs:*"], ["s3:*"], None]
    new = source.render_iam(c, sts, {0: ["ec2:DescribeInstances"], 1: ["s3:GetObject"]})
    assert '"Action": ["ec2:DescribeInstances"]' in new and '"Action": ["s3:GetObject"]' in new
    assert '"NotAction": "iam:*"' in new

    ts = "new iam.CfnManagedPolicy(this, 'App', { policyDocument: new iam.PolicyDocument() });\n"
    with pytest.raises(StageStop, match="policyDocument"):
        source.statements(_one(tmp_path, "p.ts", ts, "App", "CfnManagedPolicy"))


def test_l1_attribute_override_is_on_the_construct_itself(tmp_path: Path) -> None:
    text = "const t = new dynamodb.CfnTable(this, 'Events', { keySchema: [] });\n"
    c = _one(tmp_path, "t.ts", text, "Events", "CfnTable")
    new = source.render_attr(c, [("DeletionProtectionEnabled", True)], "CfnTable")
    assert new.endswith("t.addPropertyOverride('DeletionProtectionEnabled', true);\n")
    with pytest.raises(StageStop, match="existing property override"):
        source.render_attr(source.rescan(c, new), [("DeletionProtectionEnabled", True)], "CfnTable")
