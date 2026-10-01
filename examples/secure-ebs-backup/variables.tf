variable "aws_region" {
  description = "AWS Region in which to deploy the scenario."
  type        = string
  default     = "eu-central-1"
}

variable "environment" {
  description = "Environment suffix and tag."
  type        = string
  default     = "dev"
}

variable "availability_zone" {
  description = "Availability Zone for the demonstration EBS volume."
  type        = string
  default     = "eu-central-1a"
}

variable "operator_principal_arns" {
  description = "IAM role/user ARNs allowed to assume the read-only operator role."
  type        = list(string)
}

variable "administrator_principal_arns" {
  description = "IAM role/user ARNs that administer the key and vault policy; include the Terraform deployment role."
  type        = list(string)
}
