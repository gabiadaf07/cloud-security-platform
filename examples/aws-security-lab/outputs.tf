output "vpc_id" {
  value = aws_vpc.lab.id
}

output "database_endpoint" {
  value = aws_db_instance.monitoring.address
}

output "database_secret_arn" {
  value     = aws_db_instance.monitoring.master_user_secret[0].secret_arn
  sensitive = true
}

output "temporary_workload_role_arn" {
  value = aws_iam_role.workload.arn
}
