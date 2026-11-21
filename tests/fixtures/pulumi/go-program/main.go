package main

import (
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/vpc"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Bastion host access. Opened "temporarily" in 2025.
		bastionSg, err := ec2.NewSecurityGroup(ctx, "bastion-sg", &ec2.SecurityGroupArgs{
			Description: pulumi.String("bastion"),
			VpcId:       pulumi.String("vpc-0example"),
			Ingress: ec2.SecurityGroupIngressArray{
				&ec2.SecurityGroupIngressArgs{Protocol: pulumi.String("tcp"), FromPort: pulumi.Int(22), ToPort: pulumi.Int(22), CidrBlocks: pulumi.StringArray{pulumi.String("0.0.0.0/0")}, Description: pulumi.String("SSH from anywhere")},
				// monitoring stays as it is
				&ec2.SecurityGroupIngressArgs{Protocol: pulumi.String("tcp"), FromPort: pulumi.Int(9100), ToPort: pulumi.Int(9100), CidrBlocks: pulumi.StringArray{pulumi.String("10.0.0.0/16")}, Description: pulumi.String("node exporter")},
			},
		})
		if err != nil {
			return err
		}

		web, err := ec2.NewSecurityGroup(ctx, "web-sg", &ec2.SecurityGroupArgs{Description: pulumi.String("web"), VpcId: pulumi.String("vpc-0example")})
		if err != nil {
			return err
		}
		_, err = vpc.NewSecurityGroupIngressRule(ctx, "web-https", &vpc.SecurityGroupIngressRuleArgs{
			SecurityGroupId: web.ID(),
			IpProtocol:      pulumi.String("tcp"),
			FromPort:        pulumi.Int(443),
			ToPort:          pulumi.Int(443),
			CidrIpv4:        pulumi.String("0.0.0.0/0"),
		})
		if err != nil {
			return err
		}

		if err := storage(ctx); err != nil {
			return err
		}
		ctx.Export("bastionId", bastionSg.ID())
		return nil
	})
}
