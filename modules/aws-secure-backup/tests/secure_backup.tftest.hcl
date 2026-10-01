mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
      key_id = "11111111-2222-3333-4444-555555555555"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:eu-central-1:123456789012:log-group:/cloud-security-platform/monitoring-dev/aws-backup"
    }
  }

  mock_resource "aws_backup_vault" {
    defaults = {
      arn  = "arn:aws:backup:eu-central-1:123456789012:backup-vault:monitoring-dev-vault"
      name = "monitoring-dev-vault"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock-role"
      id  = "mock-role"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:role/test-runner"
      user_id    = "test-runner"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "eu-central-1"
    }
  }
}

run "secure_defaults" {
  command = apply

  variables {
    name                         = "monitoring-dev"
    administrator_principal_arns = ["arn:aws:iam::123456789012:role/terraform-deployer"]
    operator_principal_arns      = ["arn:aws:iam::123456789012:role/platform-engineer"]
  }

  assert {
    condition     = aws_kms_key.backup.enable_key_rotation
    error_message = "KMS rotation must be enabled."
  }

  assert {
    condition     = aws_backup_vault.this.kms_key_arn == aws_kms_key.backup.arn
    error_message = "The backup vault must use the customer-managed KMS key."
  }

  assert {
    condition     = aws_backup_vault_lock_configuration.this.min_retention_days == 35
    error_message = "Vault Lock must enforce the default minimum retention."
  }

  assert {
    condition     = one(one(aws_backup_plan.this.rule).lifecycle).delete_after == 35
    error_message = "The plan retention must match the secure default."
  }

  assert {
    condition     = aws_cloudwatch_log_group.evidence.kms_key_id == aws_kms_key.backup.arn
    error_message = "Evidence logs must be encrypted with the customer-managed key."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(local.operator_policy).Statement :
      statement.Sid == "ReadBackupState" && contains(statement.Action, "backup:ListRecoveryPointsByBackupVault")
    ])
    error_message = "The operator must be allowed to list recovery points."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(local.operator_policy).Statement :
      statement.Sid == "DenyDestructiveBackupActions" && statement.Effect == "Deny" && contains(statement.Action, "backup:DeleteRecoveryPoint")
    ])
    error_message = "The operator must be explicitly denied recovery-point deletion."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(local.vault_policy).Statement :
      statement.Sid == "DenyManualRecoveryPointDeletion" && statement.Effect == "Deny"
    ])
    error_message = "The vault must deny manual recovery-point deletion."
  }
}

run "reject_retention_outside_vault_lock" {
  command = plan

  variables {
    name                          = "monitoring-dev"
    administrator_principal_arns  = ["arn:aws:iam::123456789012:role/terraform-deployer"]
    operator_principal_arns       = ["arn:aws:iam::123456789012:role/platform-engineer"]
    retention_days                = 7
    vault_lock_min_retention_days = 35
  }

  expect_failures = [
    aws_backup_vault_lock_configuration.this,
  ]
}
