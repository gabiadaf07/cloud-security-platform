# Playbook: exfiltration and evidence destruction

## Trigger

`CSP-CT-006` or `CSP-CT-007`: unusual object reads, snapshot sharing, public
bucket policy changes, CloudTrail shutdown, log deletion, KMS disablement, or
backup recovery-point deletion attempts.

## Contain

1. Block the actor and external resource policy principal with explicit denies.
2. Remove unauthorized snapshot shares or public bucket access after capturing
   the current policies and CloudTrail events.
3. Re-enable trails/KMS keys and route fresh evidence to a separate security
   account when available.
4. Preserve backup vaults; never delete recovery points during investigation.

## Investigate

Correlate object/snapshot identifiers with destination accounts, source IPs,
KMS decrypt activity and data-event volume. Determine whether attempted
evidence destruction preceded or followed the data access.

## Recover

Restore affected data from a validated recovery point into an isolated
environment, verify integrity and application checks, reinstate least-privilege
policies, and retain the incident evidence for the required compliance period.
