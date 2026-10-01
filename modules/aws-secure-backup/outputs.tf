output "backup_vault_name" {
  description = "Name of the locked backup vault."
  value       = aws_backup_vault.this.name
}

output "backup_vault_arn" {
  description = "ARN of the locked backup vault."
  value       = aws_backup_vault.this.arn
}

output "backup_plan_id" {
  description = "ID of the AWS Backup plan."
  value       = aws_backup_plan.this.id
}

output "kms_key_arn" {
  description = "KMS key used by the vault and suitable for source EBS encryption."
  value       = aws_kms_key.backup.arn
}

output "operator_role_arn" {
  description = "Read-only role used by the permitted/denied access test."
  value       = aws_iam_role.operator.arn
}

output "backup_service_role_arn" {
  description = "EBS-scoped service role assumed by AWS Backup."
  value       = aws_iam_role.backup.arn
}

output "evidence_log_group_name" {
  description = "CloudWatch log group containing Backup job state-change evidence."
  value       = aws_cloudwatch_log_group.evidence.name
}
