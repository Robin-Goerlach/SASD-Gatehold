# ADR-0010: Gate activation on controller recovery

- Status: accepted
- Date: 2026-09-18

## Context

A durable pending-activation record is useful only if every controller process
examines it before accepting a new privileged mutation. Calling recovery from an
optional application callback would leave a race in which an activation request
could reach PF first. The controller also needs an explicit response to audit
loss and to terminal rollback failure; continuing to accept writes after either
condition would hide uncertainty and compound damage.

## Decision

Gatehold introduces a controller lifecycle gate around `PfActivationService`.
Every new instance begins in `created`. Its synchronous `start()` transition
holds the lifecycle lock, emits startup intent, and calls `recover_pending()`
before it can enter `ready`. Activation dispatch is accepted only in `ready`.

Startup has three terminal outcomes:

- `ready` when recovery and both controller audit boundaries succeed;
- `read_only` when recovery succeeds but durable audit evidence is unavailable;
- `blocked` when recovery cannot establish a safe state.

After startup, a rollback failure moves the controller from `ready` to
`blocked`. Audit, transaction-store, cleanup, or cross-process conflict results
move it to `read_only`. These states are monotonic for the process lifetime. An
operator must diagnose the cause and restart a newly constructed controller;
there is no request that resets a degraded controller in place.

One mutex covers startup, dispatch, and state transitions. A request arriving
while startup recovery is running waits behind recovery. A request arriving
before startup begins, or after a degraded terminal state, is rejected without
calling the activation service.

## Consequences

- Recovery is a mandatory activation precondition rather than an integration
  convention.
- A queued request cannot overtake restart rollback.
- Audit loss permits inspection by future read-only controller operations but
  no PF mutation.
- Critical rollback uncertainty stops all later activation dispatch.
- Repeated `start()` calls are idempotent and do not repeat PF recovery.
- The controller lifecycle is testable without a root process or host firewall.

## Security impact

The gate narrows fail-open opportunities at process startup and after degraded
operations. Rejected pre-start requests use a fixed audit correlation value, so
an unvalidated operation ID cannot inject sensitive or hostile text into the
journal. Stable `GH-CTL-*` events distinguish ordinary gating, read-only
degradation, failed recovery, and critical rollback failure.

The lifecycle object is not itself a privilege boundary. The production daemon
must still own its state directories, authenticate a bounded local protocol,
drop unnecessary privileges, and apply OpenBSD `pledge`/`unveil` constraints.

## Operational impact

`read_only` and `blocked` are operator-visible terminal process states. A
production supervisor must expose them in health reporting and must not restart
blindly in a loop. Recovery diagnostics and pending state must be preserved for
investigation.

## Alternatives considered

- Letting each caller invoke recovery was rejected because the ordering could
  not be enforced centrally.
- Automatically returning from `read_only` to `ready` when one append succeeds
  was rejected because a gap in durable evidence still requires review.
- Retrying after rollback failure was rejected because the active PF state is
  uncertain and further automatic mutation can make recovery harder.
- Running recovery concurrently with request handling was rejected because a
  new activation could overwrite the safety action or its evidence.
