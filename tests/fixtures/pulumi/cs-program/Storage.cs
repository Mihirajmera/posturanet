using System.Collections.Generic;
using System.Text.Json;
using Pulumi.Aws.Iam;
using Pulumi.Aws.S3;

static class Storage
{
    public static void Create()
    {
        var assets = new Bucket("assets", new() { BucketName = "acme-assets" });
        new BucketPublicAccessBlock("assets-pab", new()
        {
            Bucket = assets.Id,
            BlockPublicAcls = false,
            IgnorePublicAcls = true,
        });

        new Policy("app", new()
        {
            Name = "app",
            PolicyDocument = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["Version"] = "2012-10-17",
                ["Statement"] = new[]
                {
                    new Dictionary<string, object?>
                    {
                        ["Sid"] = "App",
                        ["Effect"] = "Allow",
                        ["Action"] = new[]
                        {
                            "ec2:*",
                            "logs:*",
                        },
                        ["Resource"] = "*",
                    },
                },
            }),
        });
    }
}
