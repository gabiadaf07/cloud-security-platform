# Cloud Security Platform

Cloud Security Platform is a reusable security-control repository. It combines
secure Terraform modules, policy scanners, evidence automation and incident
playbooks. The Monitoring Platform is the workload used to demonstrate that
the controls work end to end.

## Architecture

```text
source change
    │
    ├─ secrets ─ SAST ─ dependencies ─ Dockerfile ─ Kubernetes/RBAC ─ Terraform
    │                                                                  │
    └──────────────────── deployment security gate ────────────────────┘
                                      │
                           Monitoring Platform
                                      │
                    segmented AWS lab + secure backup
                                      │
                CloudTrail investigation + evidence manifest
```

| Capability | Reusable implementation | Demonstration |
|---|---|---|
| Six-stage DevSecOps gate | [GitHub workflow](.github/workflows/devsecops.yml) | Every stage exits non-zero on critical/high findings |
| Secure AWS architecture | [AWS security lab](examples/aws-security-lab) | Segmented VPC, isolated DB subnets, STS role, KMS and RDS-managed Secrets Manager secret |
| Terraform misconfiguration detection | [21-rule scanner](security_platform/scanners/terraform_scanner.py) | Tests prove 12+ distinct categories, including public databases, open ingress and wildcard IAM |
| Secure backup control | [AWS Backup module](modules/aws-secure-backup) | Encrypted EBS example, Vault Lock, least-privilege roles and allowed/denied test |
| CloudTrail investigation | [Investigator](security_platform/investigation/cloudtrail_investigator.py) | Credential abuse, privilege escalation, exfiltration and evidence destruction fixtures |
| Compliance evidence | [Control catalog](controls/control-catalog.json) and [collector](security_platform/compliance/evidence_collector.py) | NIST CSF, CIS AWS/Kubernetes, AWS FSBP and NIST 800-207 mappings |
| Container and Kubernetes hardening | [Monitoring workload](monitoring-platform) and [validator](security_platform/scanners/kubernetes_scanner.py) | Non-root container, read-only root filesystem, default-deny network and scoped RBAC |
| Threat-informed design | [STRIDE](docs/threat-models/stride.md) and [Zero Trust](docs/threat-models/zero-trust.md) | Trust boundaries, residual risks and verification evidence |

## Run locally

```bash
# Unit and security-rule tests
python3 -m unittest discover -s tests -v

# The custom gates used by CI
python3 -m security_platform.scanners.terraform_scanner modules examples --fail-on HIGH
python3 -m security_platform.scanners.kubernetes_scanner monitoring-platform/k8s --fail-on HIGH

# Produce the compliance evidence manifest
python3 -m security_platform.compliance.evidence_collector

# Triage an exported CloudTrail file
python3 -m security_platform.investigation.cloudtrail_investigator cloudtrail.json \
  --format json --output reports/cloudtrail-alerts.json

# Validate the first complete control scenario
terraform -chdir=modules/aws-secure-backup init -backend=false
terraform -chdir=modules/aws-secure-backup test
```

## First vertical slice: secure AWS backup

The backup module creates a customer-managed KMS key, encrypted vault, EBS-only
service role, tag-based plan, Vault Lock, read-only operator role and encrypted
job-event evidence. The [secure EBS example](examples/secure-ebs-backup) provides
the protected volume. The runtime contract proves that recovery points can be
listed but not deleted:

```bash
./scripts/verify-access.sh <operator-role-arn> <backup-vault-name>
```

See the [backup playbook](docs/secure-backup-playbook.md) before deployment.
Compliance-mode Vault Lock becomes immutable after its cooling-off period, so
the module defaults to reversible governance mode.

## LocalStack deployment

The free local profile deploys the portable part of the platform—segmented
network resources, IAM/STS, KMS, Secrets Manager and an encrypted/versioned
evidence bucket—and then verifies it through AWS APIs:

```bash
make localstack-up
make localstack-verify
make localstack-down
```

See the [LocalStack deployment guide](docs/localstack-deployment.md) for the
fidelity boundary. AWS Backup itself requires an eligible LocalStack paid plan,
so Vault Lock remains a Terraform contract test plus an AWS integration test.

## Security-lab cost and scope

The AWS lab contains chargeable resources, including RDS, interface endpoints,
KMS and AWS Backup. Run `terraform plan`, review regional pricing and deploy in
a disposable development account. CloudTrail organization-trail ownership is
kept outside the lab; the investigator consumes exported organization/account
trail events without creating a duplicate trail.

The lightweight custom scanners inspect source configuration and complement,
not replace, plan-aware and runtime cloud controls.
