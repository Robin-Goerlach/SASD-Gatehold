# ADR-0008: Require authorized, verified, and confirmed PF activation

- Status: accepted
- Date: 2026-09-18

## Context

Native syntax validation proves only that PF can parse a ruleset. It does not
prove that an administrator authorized the change, that the management path
survives activation, or that the new policy should become the rollback target.
An activation error can disconnect the administrator or disrupt forwarding even
when the ruleset is syntactically valid.

Gatehold therefore needs one coordinator that owns the complete mutation
sequence and never treats a requested goal as authorization.

## Decision

The activation service requires all of the following before it commits a
revision:

1. a trusted authorizer accepts the operation and returns a safe decision ID;
2. an existing last-known-good revision is available for rollback;
3. the target immutable revision exists and differs from last known good;
4. `/sbin/pfctl -nf` accepts the stored revision immediately before activation;
5. an intent record is durably appended before `/sbin/pfctl -f` is invoked;
6. every configured health probe succeeds within its contract;
7. a separate trusted confirmation gate explicitly confirms the active
   revision within the requested bounded interval;
8. the last-known-good marker is atomically advanced only after verification
   and confirmation.

The authorizer, probes, and confirmation gate are injected trusted interfaces.
The caller cannot replace authorization with a Boolean flag. Authorization
references are passed to the authorizer but are not copied into the audit
journal; only the returned decision ID is recorded.

Any ambiguous load result, failed probe, missing confirmation, commit failure,
or post-mutation audit failure before the durable commit boundary invokes the
previous last-known-good revision.
Rollback does not depend on the requesting web session. Failure to reload PF or
restore the marker becomes a critical `rollback_failed` terminal state.

Calls are serialized within one activation-service instance. A durable pending
record additionally prevents a second process from beginning another activation
and supplies restart-recovery state. The native loader uses a fixed absolute
executable path, an argument vector, bounded diagnostic capture, and a timeout.
It never constructs a shell command.

## Consequences

- A successful activation has explicit authorization, native revalidation,
  post-load verification, confirmation, and a durable rollback target.
- Preparation alone still cannot activate or promote a revision.
- Audit failure before mutation prevents activation; audit failure after
  mutation causes rollback even when that rollback cannot be journaled.
- Native output remains available to the immediate caller but is excluded from
  audit events by default.
- Bootstrap must establish an initial last-known-good revision before this
  service can activate another revision.
- The synchronous prototype depends on trusted probe and confirmation
  implementations honoring the supplied timeout contracts.

## Security impact

The future privileged controller is the trust boundary that will instantiate
the authorizer, loader, probes, and confirmation gate. The unprivileged API must
not choose executable paths, invent authorization decisions, or provide probe
code. Approval and confirmation IDs are correlation evidence, not secrets or
bearer tokens.

The current implementation is not yet production-safe. Durable pending state,
restart recovery, a recovery-gated lifecycle, and bounded PF/TCP probes now
exist as library components. An authenticated bounded protocol session also
dispatches through the lifecycle. A hardened daemon and listener,
application/data-path probes, independently enforced confirmation deadlines, a
production authorization provider, and real OpenBSD activation tests are still
required before the service is exposed.

## Alternatives considered

- Loading immediately after syntax validation was rejected because it has no
  authorization, health verification, or rollback coordination.
- Marking the target last known good before activation was rejected because a
  syntactically valid ruleset may still break connectivity.
- Trusting the caller's `approved` Boolean was rejected because that collapses
  the authorization boundary into untrusted request data.
- Continuing after an audit failure was rejected because an untraceable
  privileged mutation is not an acceptable degraded mode.
- Relying only on PF's failed-load atomicity was rejected because timeouts and
  supervision failures can leave the controller uncertain about active state.
