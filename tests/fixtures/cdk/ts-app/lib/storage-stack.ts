import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

export class StorageStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    new s3.Bucket(this, 'Assets', {
      bucketName: 'acme-assets',
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const events = new dynamodb.Table(this, 'Events', {
      tableName: 'events',
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    });
    events.grantReadData(new cdk.aws_iam.AccountRootPrincipal());
  }
}
