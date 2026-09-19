# ADR-0014: Run controller recovery before service admission

- Status: accepted
- Date: 2026-09-19

## Context

The local listener can securely serve one connection, but a long-running
controller needs an owner for recovery ordering, repeated admission, stop
requests, error limits, and shutdown reporting. An unbounded `while (true)` loop
would hide failure storms and could expose the protocol before pending firewall
state has been recovered. Abruptly cancelling an in-flight activation could
also interrupt commit or rollback at the most dangerous point.

## Decision

Gatehold adds `ControllerService`, a stop-token-driven library run loop. It uses
the narrow `ControllerConnectionAcceptor` interface, implemented by
`LocalControllerListener`, so orchestration can be failure-injection tested
without opening a real socket or touching PF.

Each run performs this sequence:

1. validate all loop limits without side effects;
2. append `GH-SVC-0001` startup intent;
3. call `PrivilegedPfController::start()` unconditionally;
4. stop without opening the listener if configuration or startup audit failed;
5. honor a pre-existing stop request after recovery;
6. start and audit the listener;
7. append `GH-SVC-0002` before entering repeated admission;
8. serve one complete protocol session at a time;
9. stop the listener and append `GH-SVC-0003`.

Recovery therefore runs even when service configuration is invalid,
service-level audit is unavailable, or stop was already requested. Listener
exposure never occurs in these cases. A `blocked` or `read_only` controller may
still expose status when the service and listener audits are healthy; activation
remains rejected by the controller lifecycle gate.

The accept poll interval is 10–1000 milliseconds and determines idle stop
responsiveness. Protocol I/O timeout is positive and at most 60 seconds. One to
100 consecutive listener errors can be configured; reaching the limit emits
`GH-SVC-2003` and terminates the loop. A successful idle poll or completed
session resets the error streak. Peer rejection, malformed input, protocol
timeout, and other terminal client-session results increment protocol-failure
telemetry but do not count as listener failures.

Stop is cooperative between sessions. The service does not cancel a request
already inside authorization, PF loading, verification, confirmation, commit,
or rollback. The active transaction must reach its own bounded terminal state
before listener shutdown. This preserves firewall safety at the cost of a
longer shutdown deadline.

Only one `run()` invocation may own a service instance. A second call returns
`GH-SVC-1002`. Lifetime counters saturate rather than wrap.

## Consequences

- Recovery-before-admission is encoded in one reusable orchestration boundary.
- Idle stop latency is bounded by the accept poll interval.
- Repeated infrastructure failure terminates instead of spinning forever.
- Hostile or broken clients do not take down an otherwise healthy listener.
- Shutdown may wait for an in-flight activation's independently bounded safety
  workflow; an operator must not treat process termination as cancellation.
- The service remains a library component. The synchronous signal bridge is a
  separate library boundary; process supervision belongs to a future executable.

## Security impact

The service cannot bypass `PrivilegedPfController`, and a caller cannot turn a
goal into authorization by merely starting the run loop. The protocol's kernel
peer checks and the activation authorizer remain mandatory.

Service events contain controller state, configured error limit, and saturated
aggregate counters. They contain no socket path, peer payload, authorization
reference, native command output, probe endpoint, or credential.

## Operational impact

A process entry point should start `PosixSignalStopBridge` before other threads,
pass its token to the service, then allow enough time for the current
transaction to complete. A hard kill can still leave durable pending state,
which the next startup recovery is designed to resolve.

Operators should alert on `GH-SVC-2003`, `GH-SVC-2004`, and `GH-SVC-2005`.
Repeated client-level `GH-IPC-*` failures require rate controls at the future
process boundary; they deliberately do not consume the listener-error budget.

## Alternatives considered

- Starting the listener before recovery was rejected because requests could
  race unresolved activation state.
- Cancelling an activation on stop was rejected because interruption can turn a
  recoverable transaction into an ambiguous firewall state.
- Treating every malformed client as a service failure was rejected because a
  local untrusted peer could then stop the controller.
- Retrying listener failures forever was rejected because persistent descriptor
  or filesystem failure would create a hot loop and hide outage severity.
- Installing signal handlers inside the library was rejected because process
  policy and async-signal-safe wakeup design belong to the daemon entry point.
