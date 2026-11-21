using System.Collections.Generic;
using Pulumi;
using Pulumi.Aws.Ec2;
using Aws = Pulumi.Aws;

return await Deployment.RunAsync(() =>
{
    // Bastion host access. Opened "temporarily" in 2025.
    var bastionSg = new SecurityGroup("bastion-sg", new()
    {
        Description = "bastion",
        VpcId = "vpc-0example",
        Ingress = new[]
        {
            new Aws.Ec2.Inputs.SecurityGroupIngressArgs { Protocol = "tcp", FromPort = 22, ToPort = 22, CidrBlocks = new[] { "0.0.0.0/0" }, Description = "SSH from anywhere" },
            // monitoring stays as it is
            new Aws.Ec2.Inputs.SecurityGroupIngressArgs { Protocol = "tcp", FromPort = 9100, ToPort = 9100, CidrBlocks = new[] { "10.0.0.0/16" }, Description = "node exporter" },
        },
    });

    var web = new SecurityGroup("web-sg", new() { Description = "web", VpcId = "vpc-0example" });
    new Aws.Vpc.SecurityGroupIngressRule("web-https", new()
    {
        SecurityGroupId = web.Id,
        IpProtocol = "tcp",
        FromPort = 443,
        ToPort = 443,
        CidrIpv4 = "0.0.0.0/0",
    });

    Storage.Create();

    return new Dictionary<string, object?>
    {
        ["bastionId"] = bastionSg.Id,
    };
});
