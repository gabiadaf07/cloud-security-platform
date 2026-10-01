# STRIDE assessment

## Scope

The assessment covers the developer-to-deployment path, Terraform execution,
AWS control plane, backup vault, evidence store, container registry, and the
Monitoring Platform Kubernetes workload.

| STRIDE | Representative threat | Preventive control | Detection/evidence |
|---|---|---|---|
| Spoofing | Stolen developer or AWS credentials assume a privileged role | MFA-conditioned role assumption, temporary STS sessions, no IAM access keys | CloudTrail `AssumeRole`, console-login and credential-change rules |
| Tampering | Backup policy, KMS key or Kubernetes manifest is weakened | Terraform review, Vault Lock, explicit deny policies, six-stage CI gate | Git history, Terraform plan, CloudTrail evidence-destruction alert |
| Repudiation | Operator denies changing IAM or deleting evidence | Multi-Region CloudTrail responsibility, job-event logs and hashed evidence manifests | Principal ARN, source IP, event ID and artifact SHA-256 |
| Information disclosure | Public database, open security group, leaked secret or overbroad RBAC | Private DB subnets, custom Terraform scanner, Secrets Manager, default-deny NetworkPolicy | CI findings and CloudTrail data-read alerts |
| Denial of service | Destructive API calls remove backups or exhaust workload capacity | Vault Lock, recovery-point delete deny, resource requests/limits, two replicas | Backup job events and Kubernetes health probes |
| Elevation of privilege | Wildcard IAM/RBAC or role-policy attachment grants admin | IAM/RBAC scanners, scoped workload role, explicit operator deny | CloudTrail IAM escalation rules and CI report |

## Trust boundaries

1. Developer workstation to GitHub is untrusted until secrets and SAST gates pass.
2. GitHub runner to AWS is a privileged boundary and must use OIDC/temporary
   credentials in a real deployment workflow.
3. Application subnets to database subnets are separated by route tables and
   security-group references.
4. Kubernetes workload identity is separate from cluster administration.
5. Runtime logs become audit evidence only after encryption, access control,
   retention and integrity hashing are applied.

## Residual risks

- The lightweight Terraform scanner evaluates literal resource configuration,
  not every value produced by modules or expressions. CI should retain a
  plan-aware scanner as defense in depth.
- An administrator allow-listed in a vault policy can weaken governance-mode
  controls. Compliance-mode promotion requires separate approval.
- CloudTrail data events can be high-volume and must be explicitly enabled for
  protected S3/Lambda resources.
