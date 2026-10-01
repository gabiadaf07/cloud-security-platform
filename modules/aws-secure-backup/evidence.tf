resource "aws_cloudwatch_log_group" "evidence" {
  name              = "/cloud-security-platform/${var.name}/aws-backup"
  retention_in_days = var.evidence_retention_days
  kms_key_id        = aws_kms_key.backup.arn
  tags              = local.common_tags
}

locals {
  eventbridge_logs_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.evidence.arn}:*"
      Principal = {
        Service = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
      }
    }]
  })
}

resource "aws_cloudwatch_log_resource_policy" "eventbridge" {
  policy_name     = "${var.name}-backup-events"
  policy_document = local.eventbridge_logs_policy
}

resource "aws_cloudwatch_event_rule" "backup_jobs" {
  name        = "${var.name}-backup-job-evidence"
  description = "Capture AWS Backup job state changes as audit evidence"

  event_pattern = jsonencode({
    source = ["aws.backup"]
    detail-type = [
      "Backup Job State Change",
      "Copy Job State Change",
      "Restore Job State Change"
    ]
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "evidence" {
  rule = aws_cloudwatch_event_rule.backup_jobs.name
  arn  = aws_cloudwatch_log_group.evidence.arn

  depends_on = [aws_cloudwatch_log_resource_policy.eventbridge]
}
