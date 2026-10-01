locals {
  name       = "csp-local"
  account_id = data.aws_caller_identity.local.account_id
  tags = {
    Environment     = "localstack"
    ManagedBy       = "Terraform"
    SecurityControl = "cloud-security-platform"
  }
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.90.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = local.name })
}

resource "aws_subnet" "application" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.90.10.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${local.name}-application", Tier = "private-application" })
}

resource "aws_subnet" "database" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.90.20.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${local.name}-database", Tier = "isolated-database" })
}

resource "aws_route_table" "application" {
  vpc_id = aws_vpc.lab.id
  tags   = merge(local.tags, { Name = "${local.name}-application" })
}

resource "aws_route_table" "database" {
  vpc_id = aws_vpc.lab.id
  tags   = merge(local.tags, { Name = "${local.name}-database" })
}

resource "aws_route_table_association" "application" {
  subnet_id      = aws_subnet.application.id
  route_table_id = aws_route_table.application.id
}

resource "aws_route_table_association" "database" {
  subnet_id      = aws_subnet.database.id
  route_table_id = aws_route_table.database.id
}

resource "aws_security_group" "application" {
  name        = "${local.name}-application"
  description = "Local application tier"
  vpc_id      = aws_vpc.lab.id
  tags        = local.tags
}

resource "aws_security_group" "database" {
  name        = "${local.name}-database"
  description = "Local database tier"
  vpc_id      = aws_vpc.lab.id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "database_from_application" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.application.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"

  # LocalStack reads this value back as "account-id/sg-id", while AWS and the
  # provider configuration use "sg-id". Ignore only that emulator-only
  # normalization so repeated local plans remain idempotent.
  lifecycle {
    ignore_changes = [referenced_security_group_id]
  }
}

resource "aws_kms_key" "data" {
  description             = "LocalStack data and evidence key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.name}-data"
  target_key_id = aws_kms_key.data.key_id
}

resource "aws_secretsmanager_secret" "database" {
  name       = "${local.name}/monitoring/database"
  kms_key_id = aws_kms_key.data.arn
  tags       = local.tags
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username = "monitoring_local"
    password = var.local_database_password
  })
}

resource "aws_s3_bucket" "evidence" {
  bucket = "${local.name}-evidence-${local.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

locals {
  workload_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root" }
    }]
  })
  workload_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadDatabaseSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.database.arn
      },
      {
        Sid      = "WriteEvidence"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/runtime/*"
      },
      {
        Sid      = "DecryptDataKey"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.data.arn
      }
    ]
  })
}

resource "aws_iam_role" "workload" {
  name                 = "${local.name}-temporary-workload"
  assume_role_policy   = local.workload_trust_policy
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "workload" {
  name   = "local-least-privilege"
  role   = aws_iam_role.workload.id
  policy = local.workload_policy
}
