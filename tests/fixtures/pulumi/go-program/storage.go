package main

import (
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func storage(ctx *pulumi.Context) error {
	assets, err := s3.NewBucket(ctx, "assets", &s3.BucketArgs{Bucket: pulumi.String("acme-assets")})
	if err != nil {
		return err
	}
	_, err = s3.NewBucketPublicAccessBlock(ctx, "assets-pab", &s3.BucketPublicAccessBlockArgs{
		Bucket:           assets.ID(),
		BlockPublicAcls:  pulumi.Bool(false),
		IgnorePublicAcls: pulumi.Bool(true),
	})
	if err != nil {
		return err
	}

	_, err = iam.NewPolicy(ctx, "app", &iam.PolicyArgs{
		Name: pulumi.String("app"),
		Policy: pulumi.String(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Sid": "App",
				"Effect": "Allow",
				"Action": [
					"ec2:*",
					"logs:*"
				],
				"Resource": "*"
			}]
		}`),
	})
	return err
}
