#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose_file="$repository_root/docker-compose.localstack.yml"
terraform_dir="$repository_root/examples/localstack-security-lab"
endpoint=${LOCALSTACK_ENDPOINT:-http://localhost:4566}
action=${1:-up}

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}
export AWS_EC2_METADATA_DISABLED=true
export AWS_PAGER=""
export TF_VAR_localstack_endpoint="$endpoint"
export TF_VAR_local_database_password=${LOCAL_DATABASE_PASSWORD:-localstack-ephemeral-value}

wait_until_ready() {
  for _ in $(seq 1 60); do
    if curl -fsS "$endpoint/_localstack/health" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "LocalStack did not become ready within 60 seconds" >&2
  return 1
}

verify() {
  local bucket role secret vpc
  bucket=$(terraform -chdir="$terraform_dir" output -raw evidence_bucket)
  role=$(terraform -chdir="$terraform_dir" output -raw workload_role_name)
  secret=$(terraform -chdir="$terraform_dir" output -raw database_secret_arn)
  vpc=$(terraform -chdir="$terraform_dir" output -raw vpc_id)

  aws --endpoint-url "$endpoint" sts get-caller-identity >/dev/null
  aws --endpoint-url "$endpoint" ec2 describe-vpcs --vpc-ids "$vpc" >/dev/null
  aws --endpoint-url "$endpoint" s3api get-bucket-encryption --bucket "$bucket" >/dev/null
  aws --endpoint-url "$endpoint" s3api get-bucket-versioning --bucket "$bucket" \
    --query 'Status' --output text | grep -qx Enabled
  aws --endpoint-url "$endpoint" s3api get-public-access-block --bucket "$bucket" >/dev/null
  aws --endpoint-url "$endpoint" secretsmanager describe-secret --secret-id "$secret" >/dev/null
  aws --endpoint-url "$endpoint" iam get-role --role-name "$role" >/dev/null
  aws --endpoint-url "$endpoint" sts assume-role \
    --role-arn "arn:aws:iam::000000000000:role/$role" \
    --role-session-name local-deploy-verification >/dev/null
  echo "PASS: LocalStack deploy, encryption, versioning, private network and temporary role verified"
}

case "$action" in
  up)
    docker compose -f "$compose_file" up -d
    wait_until_ready
    terraform -chdir="$terraform_dir" init -backend=false
    terraform -chdir="$terraform_dir" apply -auto-approve
    verify
    ;;
  verify)
    wait_until_ready
    verify
    ;;
  down)
    if curl -fsS "$endpoint/_localstack/health" >/dev/null 2>&1; then
      terraform -chdir="$terraform_dir" destroy -auto-approve
    fi
    docker compose -f "$compose_file" down --volumes
    ;;
  *)
    echo "usage: $0 [up|verify|down]" >&2
    exit 64
    ;;
esac
