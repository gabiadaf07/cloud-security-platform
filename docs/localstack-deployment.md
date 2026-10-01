# LocalStack deployment

## What this proves

The local deployment applies real Terraform provider operations against the
LocalStack edge endpoint and verifies:

- private application/database subnets and security-group segmentation;
- KMS key creation and rotation configuration;
- a Secrets Manager secret encrypted with that key;
- an S3 evidence bucket with KMS encryption, versioning and public-access blocks;
- a one-hour IAM workload role with resource-scoped permissions;
- successful temporary credential issuance through STS.

Run:

```bash
./scripts/localstack-deploy.sh up
./scripts/localstack-deploy.sh verify
./scripts/localstack-deploy.sh down
```

The default secret value is explicitly local and ephemeral. Override it without
committing a value:

```bash
LOCAL_DATABASE_PASSWORD="$(openssl rand -hex 24)" ./scripts/localstack-deploy.sh up
```

Terraform state contains the local secret value and is excluded by
`.gitignore`. Never reuse production credentials in this environment.

## Fidelity boundary

LocalStack is an API emulator, not AWS. It validates Terraform wiring and basic
service interactions, but it does not reproduce AWS networking, cryptographic
boundaries, IAM propagation or service availability guarantees.

The local security-group rule ignores changes to its source-group ID because
LocalStack reads the value back with an account-ID prefix. This exception is
limited to the emulator profile; the deployable AWS examples do not suppress
that drift.

AWS Backup is available only in eligible LocalStack paid plans. The free local
profile therefore does not pretend to validate Vault Lock or recovery-point
lifecycle behavior. Those controls remain covered by Terraform mock tests and
must receive one integration test in a disposable AWS account before release.
