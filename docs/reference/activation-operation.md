# PF activation operation

Status: **experimental library API; gated by a lifecycle object but not exposed
by a production daemon**

The activation service coordinates the only workflow allowed to replace the
active PF ruleset. It consumes an already prepared immutable revision. It does
not accept raw PF text, an executable path, or a caller-provided authorization
Boolean.

## Required collaborators

| Collaborator | Responsibility |
|---|---|
| `ActivationAuthorizer` | Verify an external authorization reference and return a decision ID |
| `RevisionStore` | Resolve target and last-known-good revisions |
| `PfctlValidator` | Re-run `/sbin/pfctl -nf` immediately before mutation |
| `PfctlLoader` | Invoke `/sbin/pfctl -f` without a shell |
| `HealthProbe` | Verify a controller-selected safety property after activation; concrete PF-info and numeric TCP probes exist |
| `ConfirmationGate` | Await explicit confirmation using the supplied deadline |
| `OperationJournal` | Durably record intent and outcome around each stage |
| `ActivationTransactionStore` | Persist phase, serialize processes, and drive restart recovery |

The production controller must construct these collaborators. Request data must
never select their implementations.

## Successful sequence

| Order | Event ID | Meaning |
|---:|---|---|
| 1 | `GH-ACT-0001` | Activation workflow started |
| 2 | `GH-AUTH-0001` | Trusted authorizer accepted the request |
| 3 | `GH-ACT-0002` | Immediate native revalidation started |
| 4 | `GH-PF-0001` | `/sbin/pfctl -nf` accepted the stored revision |
| 5 | `GH-ACT-0010` / `GH-TXN-0001` | Durable pending transaction was created |
| 6 | `GH-ACT-0003` | Ruleset replacement is about to begin |
| 7 | `GH-PF-0002` / `GH-TXN-0002` | Target loaded and phase advanced |
| 8 | `GH-ACT-0004` / `GH-PROBE-0001` | Each configured probe started and passed |
| 9 | `GH-TXN-0002` / `GH-ACT-0005` | Verified phase persisted; confirmation pending |
| 10 | `GH-CONF-0001` / `GH-TXN-0002` | Confirmation accepted; committing persisted |
| 11 | `GH-ACT-0006` / `GH-REV-0003` | Commit started; target became last known good |
| 12 | `GH-TXN-0002` / `GH-ACT-0007` | Committed phase and final event persisted |
| 13 | `GH-TXN-0004` | Pending transaction cleared |

Events contain revision and operation IDs. Activation intent also contains the
rollback revision and authorization decision ID. The original authorization
reference, native output, packet data, and probe diagnostics are not written to
the journal.

## Rollback

After a possible mutation, these conditions trigger rollback:

- rejected, timed-out, or ambiguous native load;
- failed, timed-out, or unavailable health probe;
- rejected, timed-out, or unavailable confirmation;
- failure to update the last-known-good marker;
- any audit append failure before the durable `committed` phase.

An audit or cleanup failure after the durable commit boundary does not undo an
explicitly confirmed configuration. It returns a committed warning state and
leaves enough transaction state for idempotent cleanup when necessary.

Rollback emits `GH-ACT-0008`, reloads the previous immutable revision, restores
its marker, clears the pending transaction, and finishes with `GH-ACT-0009`.
The reload is attempted even when the journal is unavailable. `GH-ACT-2001`
means rollback itself failed and requires immediate operator recovery.

## Terminal statuses

| Status | Meaning |
|---|---|
| `committed` | Target passed every gate and became last known good |
| `invalid_request` | IDs, revision, deadlines, or probe configuration are invalid |
| `authorization_denied` | Trusted authorizer rejected the operation |
| `authorization_error` | Authorization could not be verified |
| `last_known_good_unavailable` | No safe rollback revision exists |
| `target_unavailable` | Target revision is absent or unsafe |
| `native_revalidation_failed` | Immediate `/sbin/pfctl -nf` failed |
| `activation_failed` | Target load failed and rollback succeeded |
| `verification_failed_rolled_back` | A health probe failed and rollback succeeded |
| `confirmation_failed_rolled_back` | Confirmation failed or expired and rollback succeeded |
| `commit_failed_rolled_back` | Marker/final commit failed and rollback succeeded |
| `transaction_conflict` | Another process already owns a pending activation |
| `transaction_store_failed` | Durable transaction creation or phase update failed |
| `committed_with_warning` | Commit is durable but a post-commit audit append failed |
| `committed_cleanup_pending` | Commit is durable; stale transaction cleanup needs recovery |
| `audit_failed` | Audit failed before mutation, so activation did not begin |
| `audit_failed_rolled_back` | Audit failed after mutation and rollback succeeded |
| `rollback_failed` | PF reload or marker restoration failed |

## Current boundary

Linux tests use a controlled `pfctl` substitute and prove orchestration and
failure behavior without modifying the host firewall. The real OpenBSD test
currently covers only non-mutating `pfctl -nf`. The read-only daemon dispatches
the experimental authenticated session protocol through the recovery-gated
controller lifecycle, but its deny-all authorizer rejects new activation before
native validation or mutation.

Before activation can be enabled, Gatehold still needs application/data-path
probes, a real authorization provider, an out-of-session confirmation channel,
a constrained `pfctl` helper, native verification of the new daemon sandbox,
and a disposable OpenBSD network lab test. See the
[pending-activation reference](pending-activation.md),
[controller-lifecycle reference](controller-lifecycle.md), and
[health-probe reference](health-probes.md). The wire schema is documented in the
[local-controller-protocol reference](local-controller-protocol.md).
