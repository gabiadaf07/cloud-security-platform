variable "name" {
  description = "Short name used as a prefix for resources."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9_-]{1,48}$", var.name))
    error_message = "name must contain 2-49 alphanumeric, dash, or underscore characters."
  }
}

variable "resource_tag_key" {
  description = "Tag key used to select EBS volumes for backup."
  type        = string
  default     = "Backup"
}

variable "resource_tag_value" {
  description = "Tag value used to select EBS volumes for backup."
  type        = string
  default     = "secure"
}

variable "schedule" {
  description = "AWS Backup cron expression. Defaults to 05:00 UTC daily."
  type        = string
  default     = "cron(0 5 ? * * *)"
}

variable "start_window_minutes" {
  description = "Minutes after the schedule during which a job may start."
  type        = number
  default     = 60
}

variable "completion_window_minutes" {
  description = "Minutes after start during which a job must complete."
  type        = number
  default     = 180
}

variable "retention_days" {
  description = "Number of days recovery points remain in the vault."
  type        = number
  default     = 35

  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 36500
    error_message = "retention_days must be between 1 and 36500."
  }
}

variable "cold_storage_after_days" {
  description = "Days before moving recovery points to cold storage; null disables transition."
  type        = number
  default     = null

  validation {
    condition     = var.cold_storage_after_days == null || var.cold_storage_after_days >= 1
    error_message = "cold_storage_after_days must be null or at least 1."
  }
}

variable "vault_lock_min_retention_days" {
  description = "Minimum retention enforced by Vault Lock."
  type        = number
  default     = 35
}

variable "vault_lock_max_retention_days" {
  description = "Maximum retention enforced by Vault Lock."
  type        = number
  default     = 365
}

variable "vault_lock_changeable_for_days" {
  description = "Null selects governance mode. A value from 3 to 36500 selects compliance mode and its cooling-off period."
  type        = number
  default     = null

  validation {
    condition = (
      var.vault_lock_changeable_for_days == null ||
      (var.vault_lock_changeable_for_days >= 3 && var.vault_lock_changeable_for_days <= 36500)
    )
    error_message = "vault_lock_changeable_for_days must be null or between 3 and 36500."
  }
}

variable "operator_principal_arns" {
  description = "IAM principals allowed to assume the read-only backup operator role."
  type        = list(string)

  validation {
    condition     = length(var.operator_principal_arns) > 0 && alltrue([for arn in var.operator_principal_arns : can(regex("^arn:[^:]+:iam::[0-9]{12}:(role|user)/", arn))])
    error_message = "Provide at least one IAM role or user ARN."
  }
}

variable "administrator_principal_arns" {
  description = "IAM role/user ARNs allowed to administer the KMS key and change the vault policy. Include the Terraform deployment role."
  type        = list(string)

  validation {
    condition     = length(var.administrator_principal_arns) > 0 && alltrue([for arn in var.administrator_principal_arns : can(regex("^arn:[^:]+:iam::[0-9]{12}:(role|user)/", arn))])
    error_message = "Provide at least one IAM role or user ARN, including the Terraform deployment role."
  }
}

variable "evidence_retention_days" {
  description = "CloudWatch Logs retention for AWS Backup job evidence."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags applied to resources that support tags."
  type        = map(string)
  default     = {}
}
