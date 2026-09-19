# ADR-0015: Convert POSIX signals with synchronous waiting

- Status: accepted
- Date: 2026-09-19

## Context

`ControllerService` accepts a `std::stop_token`, but a future privileged daemon
must translate supervisor termination into that cooperative stop request.
Calling C++ logging, allocation, locking, or `std::stop_source` operations from
an asynchronous `sigaction()` handler is unsafe. A self-pipe handler would keep
the handler small, but adds descriptor ownership, non-blocking overflow, and
handler-uninstallation races to a security-sensitive process boundary.

## Decision

Gatehold adds the one-shot `PosixSignalStopBridge`. Its starting thread blocks
`SIGINT` and `SIGTERM` with `pthread_sigmask()` before other service threads are
created. A dedicated thread inherits that mask and synchronously consumes both
signals with `sigwait()`. The waiting thread performs the ordinary C++ work:
it requests a private `std::stop_source` and appends an allowlisted audit event.
No asynchronous signal handler is installed.

The bridge is process-exclusive. A second instance cannot consume the same
signals while one is active. Startup fails before changing the mask when the
startup intent cannot be audited. `stop()` requests worker termination, sends a
thread-directed `SIGTERM` as an internal wakeup, joins the worker, and restores
the exact prior mask. Because `pthread_sigmask()` changes the calling thread's
mask, the same thread must call `start()` and `stop()`.

The worker distinguishes its internal wakeup by observing its already-requested
worker stop token before forwarding the signal. It remains alive after the
first external signal so shutdown never needs to signal a stale thread handle.
Only the first termination signal creates the service stop request and event;
later signals are consumed while orderly shutdown is being arranged.

The bridge is intentionally one-shot. A stopped instance cannot silently
produce a fresh, unrequested service token. A new process-lifetime bridge must
be constructed for another run.

## Consequences

- Signal conversion uses normal thread context, so journal and C++ operations
  do not rely on async-signal safety.
- `ControllerService` can directly consume the bridge's stop token without
  learning about POSIX signals.
- The daemon entry point must create the bridge before starting any thread that
  must inherit blocked `SIGINT` and `SIGTERM`.
- Shutdown must occur on the starting thread. Wrong-thread calls are rejected
  without changing ownership or masks.
- The bridge does not shorten an in-flight firewall transaction; service stop
  remains cooperative between protocol sessions.

## Security impact

Failing the initial audit leaves the process signal mask unchanged and releases
the exclusive claim. Events contain only the fixed names `SIGINT` or `SIGTERM`;
they contain no peer data, command output, paths, credentials, or request
payloads. The bridge never changes signal dispositions and never creates a
general callback from signal context.

Misordered startup is still dangerous: a thread created before the bridge may
retain an unblocked termination signal and receive default process termination.
The future daemon entry point must encode and integration-test the ordering.

## Operational impact

`SIGINT` and `SIGTERM` request the same graceful service stop. Supervisors must
allow the controller's maximum in-flight safety workflow to finish before a
hard kill. Operators should investigate `GH-SIG-2001` through `GH-SIG-2007`;
these events indicate missing auditability, signal-mask failure, worker failure,
or incomplete cleanup.

## Alternatives considered

- A C++ `sigaction()` handler was rejected because the required operations are
  not async-signal-safe.
- A self-pipe handler was rejected because bounded pipe capacity and safe
  handler/descriptor teardown add avoidable edge cases.
- Polling `sigtimedwait()` was rejected because `sigwait()` plus a targeted
  internal wakeup avoids periodic wakeups and has a direct OpenBSD interface.
- Reserving `SIGUSR1` or `SIGUSR2` for shutdown was rejected because it would
  consume an application-visible signal unnecessarily.
