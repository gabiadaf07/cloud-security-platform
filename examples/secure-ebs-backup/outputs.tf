output "backup_vault_name" {
  value = module.secure_backup.backup_vault_name
}

output "operator_role_arn" {
  value = module.secure_backup.operator_role_arn
}

output "evidence_log_group_name" {
  value = module.secure_backup.evidence_log_group_name
}

output "protected_ebs_volume_id" {
  value = aws_ebs_volume.monitoring_data.id
}
