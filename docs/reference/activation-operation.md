# PF activation operation

Status: **experimental library API; not exposed by a production controller**

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
| `HealthProbe` | Verify a controller-selected safety property after activation |
| `ConfirmationGate` | Await explicit confirmation using the supplied deadline |
| `OperationJournal` | Durably record intent and outcome around each stage |

The production controller must construct these collaborators. Request data must
never select their implementations.

## Successful sequence

| Order | Event ID | Meaning |
|---:|---|---|
| 1 | `GH-ACT-0001` | Activation workflow started |
| 2 | `GH-AUTH-0001` | Trusted authorizer accepted the request |
| 3 | `GH-ACT-0002` | Immediate native revalidation started |
| 4 | `GH-PF-0001` | `/sbin/pfctl -nf` accepted the stored revision |
| 5 | `GH-ACT-0003` | Ruleset replacement is about to begin |
| 6 | `GH-PF-0002` | `/sbin/pfctl -f` loaded the target |
| 7 | `GH-ACT-0004` / `GH-PROBE-0001` | Each configured probe started and passed |
| 8 | `GH-ACT-0005` | Explicit confirmation is pending |
| 9 | `GH-CONF-0001` | Confirmation was accepted |
| 10 | `GH-ACT-0006` | Commit started |
| 11 | `GH-REV-0003` | Target became last known good |
| 12 | `GH-ACT-0007` | Transaction committed |

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
- any audit append failure.

Rollback emits `GH-ACT-0008`, reloads the previous immutable revision, restores
its marker, and finishes with `GH-ACT-0009`. The reload is attempted even when
the journal is unavailable. `GH-ACT-2001` means rollback itself failed and
requires immediate operator recovery.

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
| `audit_failed` | Audit failed before mutation, so activation did not begin |
| `audit_failed_rolled_back` | Audit failed after mutation and rollback succeeded |
| `rollback_failed` | PF reload or marker restoration failed |

## Current boundary

Linux tests use a controlled `pfctl` substitute and prove orchestration and
failure behavior without modifying the host firewall. The real OpenBSD test
currently covers only non-mutating `pfctl -nf`. No production controller calls
the activation service yet.

Before activation can be enabled, Gatehold still needs concrete bounded probes,
a real authorization provider, an out-of-session confirmation channel, a
durable pending-transaction record, startup recovery, an inter-process lock,
and a disposable OpenBSD network lab test.
