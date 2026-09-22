# ADR-0023: Verify the OpenBSD service lifecycle with a guarded harness

- Status: accepted
- Date: 2026-09-22

## Context

The experimental `rc.d` definition is portable-tested, but Linux tests cannot
prove native OpenBSD process matching, signal delivery, configuration checking,
socket ownership, or service timeouts. A laboratory test necessarily controls a
root service and could interfere with a real appliance or trigger activation
recovery if it accepted an ambiguous host state.

## Decision

Gatehold provides an opt-in ksh harness for an already provisioned disposable
OpenBSD VM. The harness binds itself to the documented installed paths and exact
service flags. It requires root, an enabled but stopped service, an absent
socket, and an absent pending-activation record before it attempts startup.

It records journal event counts, verifies that `configtest` has no journal or
socket side effects, and then exercises start, restart, and cooperative stop.
Each running state must expose a root-owned, API-group mode `0660` Unix socket.
The final stop must complete within the configured `rc.d` timeout, remove the
owned socket, and add the expected start, readiness, signal, and shutdown event
counts.

The harness does not install files, create identities, edit `rc.conf.local`,
load PF rules, remove stale paths, or adopt a running daemon. Its exit trap can
only stop an instance after this test has attempted its start.

## Consequences

- A native operator can collect repeatable evidence for the service lifecycle
  with one explicit command.
- Unexpected provisioning fails before service mutation.
- An unresolved activation transaction cannot turn a lifecycle test into a PF
  recovery action.
- Failures leave security-relevant filesystem state intact for investigation.
- Boot ordering, crash recovery, syslog routing, controller requests, and PF
  activation still require separate tests.

## Security impact

The explicit confirmation is only one guard. Platform, effective identity,
installed metadata, exact configuration, stopped state, endpoint absence, and
transaction absence are independently checked. No argument becomes a command,
path, service name, or shell program. The harness invokes fixed OpenBSD base
commands and contains no `eval`, nested shell, direct signal command, or cleanup
deletion.

The test does not claim that an enabled service makes a host disposable. The
operator remains responsible for VM isolation, console recovery, and exclusive
administrative control during the run. The harness detects a service that is
already active but cannot exclude a concurrent root operator racing `rcctl`.

## Alternatives considered

- Automatically provisioning and restoring `rc.conf.local` was rejected
  because restoration after interruption is ambiguous and could overwrite
  administrator changes.
- Deleting a stale socket or pending transaction was rejected because either
  entry may be evidence or belong to another process or recovery workflow.
- Exercising crash recovery in the same test was rejected because `SIGKILL`
  deliberately bypasses cleanup and needs a separately designed recovery
  contract.
- Running the test in portable CI was rejected because it would not exercise
  the OpenBSD service framework or Unix-socket ownership semantics.
