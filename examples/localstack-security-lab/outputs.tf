output "vpc_id" {
  value = aws_vpc.lab.id
}

output "database_subnet_id" {
  value = aws_subnet.database.id
}

output "kms_key_arn" {
  value = aws_kms_key.data.arn
}

output "database_secret_arn" {
  value = aws_secretsmanager_secret.database.arn
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.id
}

output "workload_role_name" {
  value = aws_iam_role.workload.name
}
