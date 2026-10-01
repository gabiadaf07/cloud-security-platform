locals {
  workload_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.workload_principal_arns }
      Condition = {
        Bool = { "aws:MultiFactorAuthPresent" = "true" }
      }
    }]
  })
  workload_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadOnlyManagedDatabaseSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
        Resource = aws_db_instance.monitoring.master_user_secret[0].secret_arn
      },
      {
        Sid      = "DecryptOnlyThroughSecretsManager"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.data.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com" }
        }
      }
    ]
  })
}

resource "aws_iam_role" "workload" {
  name                 = "${var.name}-temporary-workload"
  description          = "Assumed role only; no IAM users or long-lived access keys"
  assume_role_policy   = local.workload_trust_policy
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "workload" {
  name   = "database-secret-read-only"
  role   = aws_iam_role.workload.id
  policy = local.workload_policy
}
