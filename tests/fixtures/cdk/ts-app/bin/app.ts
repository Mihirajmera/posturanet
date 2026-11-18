#!/usr/bin/env node
// Synthetic CDK app for PosturaNet tests (RFC 1918 / RFC 5737 only, account 123456789012).
import * as cdk from 'aws-cdk-lib';
import { IamStack } from '../lib/iam-stack';
import { NetworkStack } from '../lib/network-stack';
import { StorageStack } from '../lib/storage-stack';

const app = new cdk.App();
new NetworkStack(app, 'network');
new StorageStack(app, 'storage');
new IamStack(app, 'iam');
