module "secure_backup" {
  source = "../../modules/aws-secure-backup"

  name                         = "monitoring-${var.environment}"
  administrator_principal_arns = var.administrator_principal_arns
  operator_principal_arns      = var.operator_principal_arns
  resource_tag_key             = "Backup"
  resource_tag_value           = "secure"
  retention_days               = 35

  # Governance mode is deliberate for the first scenario. Promote to compliance
  # mode only after testing by setting vault_lock_changeable_for_days >= 3.
  vault_lock_changeable_for_days = null

  tags = {
    Application = "monitoring-platform"
    Environment = var.environment
  }
}

# EBS backups are encrypted with the source volume key. Using the module key
# here proves encryption for both the source snapshot and the backup vault.
resource "aws_ebs_volume" "monitoring_data" {
  availability_zone = var.availability_zone
  encrypted         = true
  kms_key_id        = module.secure_backup.kms_key_arn
  size              = 1
  type              = "gp3"

  tags = {
    Name   = "monitoring-${var.environment}-backup-demo"
    Backup = "secure"
  }
}
