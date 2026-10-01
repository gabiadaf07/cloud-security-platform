resource "aws_kms_key" "data" {
  description             = "Cloud Security Platform lab data key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name}-data"
  target_key_id = aws_kms_key.data.key_id
}

resource "aws_db_subnet_group" "database" {
  name       = "${var.name}-database"
  subnet_ids = aws_subnet.database[*].id
}

resource "aws_db_instance" "monitoring" {
  identifier = "${var.name}-monitoring"

  engine                              = "postgres"
  engine_version                      = "17"
  instance_class                      = var.database_instance_class
  allocated_storage                   = 20
  max_allocated_storage               = 40
  storage_type                        = "gp3"
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.data.arn
  db_name                             = "monitoring"
  username                            = "monitoring_admin"
  manage_master_user_password         = true
  master_user_secret_kms_key_id       = aws_kms_key.data.arn
  publicly_accessible                 = false
  multi_az                            = false
  backup_retention_period             = 7
  deletion_protection                 = false
  skip_final_snapshot                 = true
  iam_database_authentication_enabled = true

  db_subnet_group_name   = aws_db_subnet_group.database.name
  vpc_security_group_ids = [aws_security_group.database.id]
}
