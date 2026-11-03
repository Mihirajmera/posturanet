variable "vpc_id" {
  type = string
}

resource "aws_security_group" "this" {
  name   = "bastion"
  vpc_id = var.vpc_id

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
