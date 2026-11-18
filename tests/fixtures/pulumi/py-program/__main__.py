"""Synthetic Pulumi program for PosturaNet tests."""

import json

import pulumi_aws as aws

bastion_sg = aws.ec2.SecurityGroup(
    "bastion-sg",
    description="bastion",
    vpc_id="vpc-0example",
    ingress=[
        # monitoring stays as it is
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=9100,
            to_port=9100,
            cidr_blocks=["10.0.0.0/16"],
            description="node exporter",
        ),
    ],
)
aws.ec2.SecurityGroupRule(
    "bastion-ssh",
    type="ingress",
    security_group_id=bastion_sg.id,
    protocol="tcp",
    from_port=22,
    to_port=22,
    cidr_blocks=["0.0.0.0/0"],
    description="SSH from anywhere",
)

web = aws.ec2.SecurityGroup("web-sg", description="web", vpc_id="vpc-0example")
aws.vpc.SecurityGroupIngressRule(
    "web-https",
    security_group_id=web.id,
    ip_protocol="tcp",
    from_port=443,
    to_port=443,
    cidr_ipv4="0.0.0.0/0",
)

assets = aws.s3.Bucket("assets", bucket="acme-assets")
aws.s3.BucketPublicAccessBlock(
    "assets-pab",
    bucket=assets.id,
    block_public_acls=True,
    block_public_policy=False,
)

aws.iam.Policy(
    "app",
    name="app",
    policy=json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "App", "Effect": "Allow", "Action": ["ec2:*", "logs:*"], "Resource": "*"}
            ],
        }
    ),
)
