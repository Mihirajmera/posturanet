resource "aws_iam_policy" "app" {
  name = "app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Compute"
        Effect   = "Allow"
        Action   = ["ec2:*", "logs:CreateLogStream"]
        Resource = "*"
      },
      {
        Sid      = "Deny"
        Effect   = "Deny"
        Action   = "ec2:TerminateInstances"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "admin" {
  name   = "admin"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "deploy" {
  name   = "deploy"
  policy = data.aws_iam_policy_document.deploy.json
}

data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "Deploy"
    effect    = "Allow"
    actions   = ["s3:*", "iam:PassRole"]
    resources = ["*"]
  }
}
