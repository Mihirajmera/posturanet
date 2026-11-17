#!/usr/bin/env python3
# Synthetic CDK app for PosturaNet tests (RFC 1918 / RFC 5737 only, account 123456789012).
import aws_cdk as cdk
from stacks.platform import PlatformStage

app = cdk.App()
PlatformStage(app, "Prod")
app.synth()
