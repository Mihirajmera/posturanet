import * as aws from "@pulumi/aws";

// Bastion host access. Opened "temporarily" in 2025.
const bastionSg = new aws.ec2.SecurityGroup("bastion-sg", {
    description: "bastion",
    vpcId: "vpc-0example",
    ingress: [
        { protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: ["0.0.0.0/0"], description: "SSH from anywhere" },
        // monitoring stays as it is
        { protocol: "tcp", fromPort: 9100, toPort: 9100, cidrBlocks: ["10.0.0.0/16"], description: "node exporter" },
    ],
});

const web = new aws.ec2.SecurityGroup("web-sg", { description: "web", vpcId: "vpc-0example" });
new aws.vpc.SecurityGroupIngressRule("web-https", {
    securityGroupId: web.id,
    ipProtocol: "tcp",
    fromPort: 443,
    toPort: 443,
    cidrIpv4: "0.0.0.0/0",
});

export const bastionId = bastionSg.id;
