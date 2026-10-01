variable "aws_region" {
  description = "Region reported by the local AWS emulator."
  type        = string
  default     = "eu-central-1"
}

variable "localstack_endpoint" {
  description = "LocalStack edge endpoint."
  type        = string
  default     = "http://localhost:4566"
}

variable "local_database_password" {
  description = "Ephemeral value written only to the local Secrets Manager emulator."
  type        = string
  sensitive   = true
}
