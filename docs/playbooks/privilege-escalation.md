# Playbook: privilege escalation

## Trigger

`CSP-CT-004` or `CSP-CT-005`: policy attachment, inline policy changes, trust
policy changes, new default policy versions or suspicious role passing.

## Contain

1. Snapshot the affected IAM policies, versions, trust documents and tags.
2. Detach the newly introduced permission or quarantine the principal with an
   explicit deny through the approved incident-response role.
3. Revoke active sessions for both the actor and any newly reachable roles.

## Investigate

Trace the session back to its original identity and review subsequent actions
performed with the elevated role. Compare policy JSON against the last approved
Terraform state and repository commit.

## Recover

Reapply reviewed infrastructure as code, validate the effective permissions
with IAM policy simulation/Access Analyzer, rotate exposed secrets, then close
the incident only after the CI and evidence controls pass again.
