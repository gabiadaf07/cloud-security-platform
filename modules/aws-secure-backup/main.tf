data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_root_arn       = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
  evidence_log_group_arn = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/cloud-security-platform/${var.name}/aws-backup"
  common_tags = merge(var.tags, {
    ManagedBy       = "Terraform"
    SecurityControl = "secure-aws-backup"
  })
  kms_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Action    = "kms:*"
        Resource  = "*"
        Principal = { AWS = concat([local.account_root_arn], var.administrator_principal_arns) }
      },
      {
        Sid      = "AllowBackupServiceUse"
        Effect   = "Allow"
        Action   = ["kms:CreateGrant", "kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*", "kms:ReEncrypt*"]
        Resource = "*"
        Principal = {
          Service = "backup.amazonaws.com"
        }
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid      = "AllowCloudWatchLogsUse"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"]
        Resource = "*"
        Principal = {
          Service = "logs.${data.aws_region.current.region}.amazonaws.com"
        }
        Condition = {
          ArnEquals = { "kms:EncryptionContext:aws:logs:arn" = local.evidence_log_group_arn }
        }
      }
    ]
  })
  vault_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyManualRecoveryPointDeletion"
        Effect    = "Deny"
        Action    = "backup:DeleteRecoveryPoint"
        Resource  = "*"
        Principal = "*"
      },
      {
        Sid       = "DenyVaultPolicyWeakening"
        Effect    = "Deny"
        Action    = ["backup:DeleteBackupVaultAccessPolicy", "backup:PutBackupVaultAccessPolicy"]
        Resource  = "*"
        Principal = "*"
        Condition = {
          ArnNotEquals = { "aws:PrincipalArn" = concat([local.account_root_arn], var.administrator_principal_arns) }
        }
      }
    ]
  })
}

resource "aws_kms_key" "backup" {
  description             = "Encryption for ${var.name} backups and evidence"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = local.kms_policy
  tags                    = local.common_tags
}

resource "aws_kms_alias" "backup" {
  name          = "alias/${var.name}-backup"
  target_key_id = aws_kms_key.backup.key_id
}

resource "aws_backup_vault" "this" {
  name        = "${var.name}-vault"
  kms_key_arn = aws_kms_key.backup.arn
  tags        = local.common_tags
}

resource "aws_backup_vault_policy" "this" {
  backup_vault_name = aws_backup_vault.this.name
  policy            = local.vault_policy
}

resource "aws_backup_vault_lock_configuration" "this" {
  backup_vault_name   = aws_backup_vault.this.name
  changeable_for_days = var.vault_lock_changeable_for_days
  min_retention_days  = var.vault_lock_min_retention_days
  max_retention_days  = var.vault_lock_max_retention_days

  lifecycle {
    precondition {
      condition     = var.vault_lock_min_retention_days <= var.retention_days && var.retention_days <= var.vault_lock_max_retention_days
      error_message = "retention_days must be inside the Vault Lock minimum/maximum range."
    }

    precondition {
      condition     = var.cold_storage_after_days == null || var.retention_days >= var.cold_storage_after_days + 90
      error_message = "AWS Backup requires retention to be at least 90 days longer than the cold-storage transition."
    }
  }
}

resource "aws_backup_plan" "this" {
  name = "${var.name}-plan"

  rule {
    rule_name                = "daily"
    target_vault_name        = aws_backup_vault.this.name
    schedule                 = var.schedule
    start_window             = var.start_window_minutes
    completion_window        = var.completion_window_minutes
    enable_continuous_backup = false

    lifecycle {
      cold_storage_after = var.cold_storage_after_days
      delete_after       = var.retention_days
    }

    recovery_point_tags = merge(local.common_tags, {
      BackupPlan = var.name
    })
  }

  tags = local.common_tags
}

resource "aws_backup_selection" "ebs" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "${var.name}-tagged-ebs"
  plan_id      = aws_backup_plan.this.id
  resources    = ["arn:${data.aws_partition.current.partition}:ec2:*:*:volume/*"]

  condition {
    string_equals {
      key   = "aws:ResourceTag/${var.resource_tag_key}"
      value = var.resource_tag_value
    }
  }
}
