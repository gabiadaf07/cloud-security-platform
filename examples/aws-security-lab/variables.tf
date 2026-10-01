variable "aws_region" {
  description = "AWS Region used by the lab."
  type        = string
  default     = "eu-central-1"
}

variable "name" {
  description = "Resource name prefix."
  type        = string
  default     = "csp-lab"
}

variable "vpc_cidr" {
  description = "CIDR for the segmented lab VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "workload_principal_arns" {
  description = "IAM principals allowed to assume the temporary workload role."
  type        = list(string)

  validation {
    condition     = length(var.workload_principal_arns) > 0
    error_message = "At least one workload principal ARN is required."
  }
}

variable "database_instance_class" {
  description = "Small instance class suitable for the lab; review cost before apply."
  type        = string
  default     = "db.t4g.micro"
}
