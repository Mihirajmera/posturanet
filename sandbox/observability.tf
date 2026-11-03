# VPC flow logs in the DEFAULT format to CloudWatch Logs (PosturaNet R1 reads the default
# format only). Retention covers the 60+ days needed for high confidence.

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/posturanet-sandbox/vpc-flow-logs"
  retention_in_days = 120
}

resource "aws_iam_role" "flow_logs" {
  name = "posturanet-sandbox-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "deliver"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
    }]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.sandbox.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
}

# PosturaNet's role. Two parts:
# 1. The allowlist PosturaNet's own code calls (same list as `posturanet init`).
# 2. ReadOnlyAccess, because `terraform plan` refreshes every resource in this root module and
#    the AWS provider needs reads beyond PosturaNet's list (tags, SSM parameter, IAM, ...).
#    For a customer account, prefer a narrower read policy scoped to what the plan touches.
resource "aws_iam_role" "posturanet" {
  name = "posturanet-sandbox-readonly"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.trusted_principal_arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "posturanet_allowlist" {
  name = "posturanet-allowlist"
  role = aws_iam_role.posturanet.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "PosturaNetReadOnly"
      Effect = "Allow"
      Action = [
        "access-analyzer:Get*",
        "access-analyzer:List*",
        "athena:GetQueryExecution",
        "athena:GetQueryResults",
        "athena:StartQueryExecution",
        "ec2:Describe*",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:Get*",
        "iam:List*",
        "iam:SimulatePrincipalPolicy",
        "logs:DescribeLogGroups",
        "logs:GetQueryResults",
        "logs:StartQuery",
        "s3:GetObject",
        "s3:ListBucket",
        "securityhub:GetFindings",
        "sts:AssumeRole",
        "sts:GetCallerIdentity",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "posturanet_plan_reads" {
  role       = aws_iam_role.posturanet.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
