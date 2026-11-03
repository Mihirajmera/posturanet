resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  skip_final_snapshot = true
}

resource "aws_dynamodb_table" "events" {
  name         = "events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length = 10
  require_numbers         = true
}
