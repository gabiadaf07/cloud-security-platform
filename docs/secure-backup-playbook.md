# Secure AWS Backup playbook

## Purpose and control boundary

This scenario protects tagged, encrypted EBS volumes in one AWS account and
Region. It demonstrates preventive controls (least-privilege IAM, KMS, Vault
Lock), detective controls (job-state evidence), and executable allowed/denied
access tests.

CloudTrail management-event coverage remains an account-level responsibility;
the module intentionally does not create a second trail. Confirm that an
organization or account trail records AWS Backup, IAM, and KMS API calls before
calling this control production-ready.

## Deploy

1. Copy `examples/secure-ebs-backup/terraform.tfvars.example` to
   `terraform.tfvars` and replace the account ID and operator principal.
2. Run `terraform init`, `terraform plan -out secure-backup.tfplan`, review the
   plan, then run `terraform apply secure-backup.tfplan`.
3. Confirm that the EBS volume has `Backup=secure`, is encrypted with the module
   CMK, and appears in the backup selection.
4. Wait for the scheduled job or start an on-demand backup using a separately
   controlled administrator role.

## Collect evidence

Create a timestamped evidence directory and capture the deployed state:

```bash
evidence_dir="evidence/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$evidence_dir"
aws backup list-backup-jobs --by-state COMPLETED >"$evidence_dir/completed-jobs.json"
aws backup list-recovery-points-by-backup-vault \
  --backup-vault-name monitoring-dev-vault >"$evidence_dir/recovery-points.json"
aws backup describe-backup-vault \
  --backup-vault-name monitoring-dev-vault >"$evidence_dir/vault.json"
aws backup get-backup-vault-access-policy \
  --backup-vault-name monitoring-dev-vault >"$evidence_dir/vault-policy.json"
aws logs filter-log-events \
  --log-group-name /cloud-security-platform/monitoring-dev/aws-backup \
  >"$evidence_dir/job-events.json"
sha256sum "$evidence_dir"/*.json >"$evidence_dir/SHA256SUMS"
```

The `evidence/` directory is gitignored because records can contain account and
resource identifiers. Move the bundle to the organization's approved evidence
store with retention and access logging.

## Test access

Run `scripts/verify-access.sh <operator-role-arn> <vault-name>`. A valid result
shows that the operator can list recovery points but receives an explicit deny
for deletion. The Terraform native tests also inspect both the identity policy
and vault resource policy without contacting AWS.

## Test restore

Restore is deliberately absent from the operator role. Use a time-bound,
separately approved restore role and restore into an isolated validation
environment. Validate volume attachment, filesystem integrity, application
checks, recovery point objective, and recovery time objective. Delete the test
volume after recording evidence; do not delete the recovery point.

## Respond to failures

1. For a failed or expired backup job, preserve the EventBridge/CloudWatch event
   and the result of `aws backup describe-backup-job`.
2. Check source-volume encryption, the selection tag, AWS Backup service-role
   permissions, and KMS grants/key policy.
3. Start an approved on-demand backup after correcting the fault.
4. Record the incident, job ID, recovery-point ARN, timestamps, and validation
   result in the evidence store.

## Teardown and compliance-mode promotion

Governance mode is the default so a privileged administrator can remove the
lock during development. Recovery points still must expire or be removed by an
authorized administrator before Terraform can destroy the vault.

Compliance mode is enabled by setting `vault_lock_changeable_for_days` to at
least `3`. After the cooling-off period, neither the lock nor a non-empty vault
can be removed until retention expires. Validate cost, retention, teardown, and
break-glass procedures before making this change.
