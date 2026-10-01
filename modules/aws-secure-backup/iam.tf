locals {
  backup_assume_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "backup.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })

  # EBS-only subset of AWSBackupServiceRolePolicyForBackup. Discovery calls
  # cannot be resource-scoped; mutating calls are limited by ARN and tags.
  backup_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DiscoverTaggedVolumes"
        Effect   = "Allow"
        Action   = ["ec2:DescribeSnapshots", "ec2:DescribeVolumes", "tag:GetResources"]
        Resource = "*"
      },
      {
        Sid      = "CreateSnapshotFromSelectedVolumes"
        Effect   = "Allow"
        Action   = "ec2:CreateSnapshot"
        Resource = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:volume/*"
        Condition = {
          StringEquals = { "aws:ResourceTag/${var.resource_tag_key}" = var.resource_tag_value }
        }
      },
      {
        Sid      = "CreateSnapshotResource"
        Effect   = "Allow"
        Action   = "ec2:CreateSnapshot"
        Resource = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.region}::snapshot/*"
      },
      {
        Sid      = "CreateTagsAndCopySnapshots"
        Effect   = "Allow"
        Action   = ["ec2:CopySnapshot", "ec2:CreateTags"]
        Resource = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.region}::snapshot/*"
      },
      {
        Sid      = "ManageBackupCreatedSnapshots"
        Effect   = "Allow"
        Action   = ["ec2:DeleteSnapshot", "ec2:ModifySnapshotAttribute", "ec2:ModifySnapshotTier"]
        Resource = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.region}::snapshot/*"
        Condition = {
          Null = { "aws:ResourceTag/aws:backup:source-resource" = "false" }
        }
      },
      {
        Sid      = "UseBackupVault"
        Effect   = "Allow"
        Action   = ["backup:CopyIntoBackupVault", "backup:DescribeBackupVault"]
        Resource = aws_backup_vault.this.arn
      },
      {
        Sid      = "TagRecoveryPoints"
        Effect   = "Allow"
        Action   = "backup:TagResource"
        Resource = "arn:${data.aws_partition.current.partition}:backup:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:recovery-point:*"
      },
      {
        Sid      = "UseBackupKeyThroughEC2"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncryptFrom", "kms:ReEncryptTo"]
        Resource = aws_kms_key.backup.arn
        Condition = {
          StringLike = { "kms:ViaService" = "ec2.${data.aws_region.current.region}.amazonaws.com" }
        }
      },
      {
        Sid      = "CreateBackupKeyGrant"
        Effect   = "Allow"
        Action   = "kms:CreateGrant"
        Resource = aws_kms_key.backup.arn
        Condition = {
          Bool = { "kms:GrantIsForAWSResource" = "true" }
        }
      }
    ]
  })

  operator_assume_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.operator_principal_arns }
    }]
  })

  operator_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadBackupState"
        Effect = "Allow"
        Action = [
          "backup:DescribeBackupJob",
          "backup:DescribeBackupVault",
          "backup:DescribeRecoveryPoint",
          "backup:GetBackupPlan",
          "backup:GetBackupSelection",
          "backup:GetBackupVaultAccessPolicy",
          "backup:ListBackupJobs",
          "backup:ListBackupSelections",
          "backup:ListRecoveryPointsByBackupVault",
          "backup:ListTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDestructiveBackupActions"
        Effect = "Deny"
        Action = [
          "backup:DeleteBackupPlan",
          "backup:DeleteBackupSelection",
          "backup:DeleteBackupVault",
          "backup:DeleteBackupVaultAccessPolicy",
          "backup:DeleteBackupVaultLockConfiguration",
          "backup:DeleteRecoveryPoint",
          "backup:PutBackupVaultAccessPolicy",
          "backup:PutBackupVaultLockConfiguration",
          "backup:StartRestoreJob",
          "backup:UpdateRecoveryPointLifecycle"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "backup" {
  name                 = "${var.name}-backup-service"
  assume_role_policy   = local.backup_assume_policy
  max_session_duration = 3600
  tags                 = local.common_tags
}

resource "aws_iam_role_policy" "backup" {
  name   = "ebs-backup-only"
  role   = aws_iam_role.backup.id
  policy = local.backup_role_policy
}

resource "aws_iam_role" "operator" {
  name                 = "${var.name}-backup-read-only"
  assume_role_policy   = local.operator_assume_policy
  max_session_duration = 3600
  tags                 = local.common_tags
}

resource "aws_iam_role_policy" "operator" {
  name   = "backup-read-only"
  role   = aws_iam_role.operator.id
  policy = local.operator_policy
}
