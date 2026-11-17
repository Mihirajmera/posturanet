from aws_cdk import RemovalPolicy, Stack, Stage
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from constructs import Construct


class PlatformStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc.from_vpc_attributes(
            self, "Vpc", vpc_id="vpc-0example", availability_zones=["us-east-1a"]
        )

        # Bastion host access. Opened "temporarily" in 2025.
        bastion_sg = ec2.SecurityGroup(self, "BastionSg", vpc=vpc, description="bastion")
        bastion_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22), "SSH from anywhere")
        bastion_sg.add_ingress_rule(
            ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(9100), description="node exporter"
        )

        s3.Bucket(
            self,
            "Assets",
            bucket_name="acme-assets",
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        iam.ManagedPolicy(
            self,
            "AppPolicy",
            managed_policy_name="app",
            statements=[
                iam.PolicyStatement(sid="App", actions=["ec2:*", "logs:*"], resources=["*"]),
            ],
        )


class PlatformStage(Stage):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        PlatformStack(self, "platform")
