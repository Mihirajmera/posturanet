import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export class IamStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    new iam.ManagedPolicy(this, 'AppPolicy', {
      managedPolicyName: 'app',
      statements: [
        new iam.PolicyStatement({
          sid: 'App',
          actions: [
            'ec2:*',
            'logs:*',
          ],
          resources: ['*'],
        }),
      ],
    });
  }
}
