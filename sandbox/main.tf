# PosturaNet sandbox: a deliberately open security group with real traffic and flow logs.
# This repo is the thing PosturaNet fixes. See README.md before applying.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Local state on purpose (state.tfstate is git-ignored). For the S3 backend test, see README.
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "posturanet-sandbox" }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "trusted_principal_arn" {
  description = "Who may assume the read-only PosturaNet role (your IAM user or SSO role ARN)."
  type        = string
}

variable "internal_client" {
  description = "Run a small client in the VPC that connects every 30 minutes (a steady internal source)."
  type        = bool
  default     = true
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_vpc" "sandbox" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "posturanet-sandbox" }
}

resource "aws_internet_gateway" "sandbox" {
  vpc_id = aws_vpc.sandbox.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.sandbox.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.sandbox.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sandbox.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

module "bastion" {
  source = "./modules/bastion"

  vpc_id    = aws_vpc.sandbox.id
  subnet_id = aws_subnet.public.id
  ami_id    = data.aws_ssm_parameter.al2023.value
}

# A steady internal source: connects to the bastion's private IP on port 22 every 30 minutes.
resource "aws_security_group" "client" {
  count  = var.internal_client ? 1 : 0
  name   = "posturanet-sandbox-client"
  vpc_id = aws_vpc.sandbox.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "client" {
  count                  = var.internal_client ? 1 : 0
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = "t3.nano"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.client[0].id]

  metadata_options {
    http_tokens = "required"
  }

  user_data = <<-EOT
    #!/bin/bash
    echo '*/30 * * * * root timeout 3 bash -c "</dev/tcp/${module.bastion.private_ip}/22" || true' > /etc/cron.d/posturanet-traffic
    dnf install -y cronie && systemctl enable --now crond
  EOT

  tags = { Name = "posturanet-sandbox-client" }
}

output "security_group_id" {
  value = module.bastion.security_group_id
}

output "bastion_public_ip" {
  value = module.bastion.public_ip
}

output "flow_log_group" {
  value = aws_cloudwatch_log_group.flow.name
}

output "posturanet_role_arn" {
  value = aws_iam_role.posturanet.arn
}
