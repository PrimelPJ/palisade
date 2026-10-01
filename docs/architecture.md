# Architecture and design decisions

## 1. Collection is separate from evaluation

Collectors (`collectors/aws.py`, `collectors/azure.py`) turn a cloud environment into an
`Inventory`: a dict of resource type to plain JSON-like records. Rules never call a cloud API.

Why it matters:

- **Same rules everywhere.** The CLI, CI, the Lambda and the Azure Function all run the
  exact same rule code, so a control cannot drift between "scheduled scan" and "real-time".
- **Testable without a cloud.** Rules are pure functions; tests feed them moto-backed or
  hand-written inventories.
- **Evidence.** `--save-inventory` writes the snapshot the findings were computed from, which
  is what an auditor asks for. `--inventory` replays it later.

## 2. Azure is scanned from read-only snapshots

`scripts/export_azure_snapshot.sh` captures posture with `az` commands that need only the
`Reader` role. The scanner itself holds no Azure credentials at all, which keeps the
privileged surface tiny and lets a security team scan a subscription they do not operate.
The collector reads both the flattened `az` CLI shape and raw ARM JSON (`properties.*`),
so the Azure Function can reuse it on resources it fetches directly from ARM.

## 3. Auto-remediation is opt-in, scoped, and incapable of loosening

A fix is marked `auto` only if it is idempotent, tightens a setting, and cannot delete data
or remove anyone's access. Everything else is emitted as an exact command for review.

Defence in depth on the remediator itself:

| Control | Implementation |
|---|---|
| Least privilege | Write actions scoped by ARN pattern (security groups, trails, keys in this account) |
| Cannot loosen | Explicit `Deny` on `iam:Create*/Delete*/Attach*/Put*`, `StopLogging`, `AuthorizeSecurityGroupIngress`, `DisableKeyRotation`, ... |
| No feedback loops | Events whose caller is the remediator's own role (AWS) or identity (Azure) are ignored |
| Blast radius | Reserved concurrency of 5; dry-run by default in Terraform |
| Observability | Structured JSON logs, X-Ray tracing, SNS alert per event with actor, source IP and fixes |
| Failure handling | DLQ on the Lambda; Event Grid retry policy with a 60-minute TTL |

## 4. Event-driven, narrowly scoped rescans

`functions/aws_lambda/handler.py` maps each monitored API call to the resource types it can
affect (`AuthorizeSecurityGroupIngress` maps to security groups only) and collects just
those. This keeps each invocation fast and cheap, and stops account-wide findings such as
root MFA from being re-alerted on every unrelated event.

IAM is a global service whose CloudTrail events are delivered only in `us-east-1`, so the
Terraform adds a us-east-1 EventBridge rule that forwards IAM events to the primary region's
bus (ca-central-1 by default).

## 5. Prevention, detection and correction for the same control

Take "storage must not be public":

1. **Prevent at review time:** Checkov policy `CKV2_PAL_3` fails the pull request.
2. **Prevent at deploy time:** the Azure Policy `deny` assignment rejects the ARM request.
3. **Detect:** rule `AZ-STG-001` finds anything created before the policy or outside Terraform.
4. **Correct:** the Azure Function patches `allowBlobPublicAccess=false` within seconds.

## 6. Suppressions are risk acceptances

A suppression must have a reason and should have an expiry. Expired suppressions stop
matching, so accepted risk is re-reviewed instead of forgotten. Suppressed findings remain
in JSON and SARIF output for audit.

## 7. SARIF output

Findings are emitted as SARIF 2.1.0 with `security-severity` scores, so GitHub code scanning
shows them alongside code findings, dedupes them across runs via `partialFingerprints`, and
lets a team triage cloud posture where they already work.
