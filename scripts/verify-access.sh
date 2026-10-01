#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <operator-role-arn> <backup-vault-name>" >&2
  exit 64
fi

operator_role_arn=$1
backup_vault_name=$2
session_name="secure-backup-access-test-$(date +%s)"

read -r access_key secret_key session_token < <(
  aws sts assume-role \
    --role-arn "$operator_role_arn" \
    --role-session-name "$session_name" \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text
)

run_as_operator() {
  AWS_ACCESS_KEY_ID="$access_key" \
  AWS_SECRET_ACCESS_KEY="$secret_key" \
  AWS_SESSION_TOKEN="$session_token" \
    aws "$@"
}

echo "[allowed] list recovery points in $backup_vault_name"
run_as_operator backup list-recovery-points-by-backup-vault \
  --backup-vault-name "$backup_vault_name" \
  --max-results 1 >/dev/null

fake_recovery_point="arn:aws:ec2:${AWS_REGION:-eu-central-1}::snapshot/snap-00000000000000000"
denied_output=$(mktemp)
trap 'rm -f "$denied_output"' EXIT

echo "[denied] delete a recovery point"
if run_as_operator backup delete-recovery-point \
  --backup-vault-name "$backup_vault_name" \
  --recovery-point-arn "$fake_recovery_point" 2>"$denied_output"; then
  echo "FAIL: destructive request unexpectedly succeeded" >&2
  exit 1
fi

if ! grep -Eqi 'AccessDenied|not authorized|explicit deny' "$denied_output"; then
  echo "FAIL: request failed, but not because access was denied" >&2
  sed -n '1,8p' "$denied_output" >&2
  exit 1
fi

echo "PASS: read access is allowed and destructive access is denied"
