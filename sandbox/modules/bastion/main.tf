variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "ami_id" {
  type = string
}

# The finding: SSH open to the internet. PosturaNet should replace the 0.0.0.0/0 rule.
resource "aws_security_group" "this" {
  name   = "posturanet-sandbox-bastion"
  vpc_id = var.vpc_id

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# No key pair: nobody can log in. sshd still accepts TCP connections, which is all the
# flow logs need to record an ACCEPT.
resource "aws_instance" "this" {
  ami                    = var.ami_id
  instance_type          = "t3.micro"
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.this.id]

  metadata_options {
    http_tokens = "required"
  }

  tags = { Name = "posturanet-sandbox-bastion" }
}

output "security_group_id" {
  value = aws_security_group.this.id
}

output "private_ip" {
  value = aws_instance.this.private_ip
}

output "public_ip" {
  value = aws_instance.this.public_ip
}
