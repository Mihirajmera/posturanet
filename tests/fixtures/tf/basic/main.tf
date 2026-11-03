terraform {
  required_version = ">= 1.5"
}

module "bastion" {
  source = "./modules/bastion"

  vpc_id = "vpc-0123456789abcdef0" # synthetic
}
