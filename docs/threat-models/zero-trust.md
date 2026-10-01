# Zero Trust assessment

The platform applies “never trust, always verify” through explicit identities,
small authorization scopes, private network paths and continuous evidence.

| Decision point | Zero Trust implementation | Verification |
|---|---|---|
| Human access | IAM roles with one-hour maximum sessions and MFA condition | CloudTrail session issuer and MFA attribute |
| Workload access | Dedicated role reads one RDS-managed secret and decrypts only through Secrets Manager | IAM policy simulation and secret access event |
| Network access | Application, public and isolated database tiers use separate route tables; DB accepts only the application SG | Terraform plan and VPC reachability analysis |
| Backup access | Read-only operator role; deletion denied by identity and vault policies; Vault Lock enforces retention | Allowed/denied runtime test |
| Kubernetes access | Non-root containers, default-deny NetworkPolicy, scoped namespaced Role without wildcards | Kubernetes scanner report |
| Software delivery | Every change passes six independent security stages before a deployment job can run | Required GitHub check results |
| Evidence access | KMS encryption, fixed retention and SHA-256 artifact manifest | Evidence collector output and KMS/CloudTrail logs |

No subnet location or successful authentication is treated as sufficient trust.
Authorization is evaluated again at the IAM policy, security group, Kubernetes
RBAC, resource policy and encryption-key boundaries.
