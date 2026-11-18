import * as aws from "@pulumi/aws";

const assets = new aws.s3.Bucket("assets", { bucket: "acme-assets" });
new aws.s3.BucketPublicAccessBlock("assets-pab", {
    bucket: assets.id,
    blockPublicAcls: false,
    ignorePublicAcls: true,
});

new aws.iam.Policy("app", {
    name: "app",
    policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Sid: "App",
            Effect: "Allow",
            Action: [
                "ec2:*",
                "logs:*",
            ],
            Resource: "*",
        }],
    }),
});
