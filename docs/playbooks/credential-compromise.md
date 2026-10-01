# Playbook: credential compromise

## Trigger

`CSP-CT-001`, `CSP-CT-002`, `CSP-CT-003` or `CSP-CT-008`, especially a new
access key, root activity, failed logins, or role assumption without MFA.

## Contain

1. Preserve the original CloudTrail object and record its object version/hash.
2. Disable the affected access key or revoke role sessions; do not delete the
   identity until its policies and relationships are captured.
3. Apply an incident-response deny policy and restrict network entry points.
4. Rotate credentials and secrets reachable by the principal.

## Investigate

Build a timeline by access-key ID, principal ARN, source IP, user agent and
session issuer. Search for IAM changes, Secrets Manager reads, KMS decrypts,
snapshot sharing and attempts to stop logging.

## Recover

Replace long-lived credentials with federation/STS, restore only required
permissions, validate MFA and monitor the principal for at least one normal
credential lifetime. Record scope, containment time and rotation evidence.
