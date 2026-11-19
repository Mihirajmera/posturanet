import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

export class NetworkStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const vpc = ec2.Vpc.fromVpcAttributes(this, 'Vpc', {
      vpcId: 'vpc-0example',
      availabilityZones: ['us-east-1a'],
    });

    // Bastion host access. Opened "temporarily" in 2025.
    const bastionSg = new ec2.SecurityGroup(this, 'BastionSg', {
      vpc,
      description: 'bastion',
    });
    bastionSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'SSH from anywhere');
    // monitoring stays as it is
    bastionSg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(9100), 'node exporter');

    const webSg = new ec2.SecurityGroup(this, 'WebSg', { vpc, description: 'web' });
    webSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443));
  }
}
