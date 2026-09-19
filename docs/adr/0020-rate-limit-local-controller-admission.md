# ADR-0020: Rate-limit local controller admission

- Status: accepted
- Date: 2026-09-19

## Context

The local controller already bounds frame size, session duration, listen
backlog, and concurrent work. It still accepted an unlimited sequence of short
connections. Every admitted connection can reach peer-authentication and audit
code, so a local process able to reach the socket could consume CPU and fill the
finite audit journal without violating any per-session bound.

Auditing every rate-limited connection would merely turn the protective control
into another log-amplification path. The control therefore needs bounded state,
a monotonic time source, bounded rejection cost, and aggregated evidence.

## Decision

`LocalControllerListener` owns a process-local sliding-window admission limiter.
The daemon default permits 30 admitted connections per 60 seconds. Library
configuration is accepted only within these hard bounds:

| Setting | Bound |
|---|---:|
| Maximum admissions | 1–1024 per window |
| Window | 100 ms–1 hour |

After `accept4()` succeeds and before peer inspection, frame parsing, protocol
audit, or dispatch, the limiter uses `std::chrono::steady_clock` to decide
whether the connection may proceed. It preallocates and retains at most the
configured number of timestamps, so admission does not allocate memory after
listener startup. Expired entries are removed independently, giving a true
sliding window rather than a fixed-window boundary burst.

An excess connection is closed immediately and returns `GH-LSN-1006`. A bounded
delay no longer than the service's accept-poll interval prevents a tight
accept/close loop under a sustained flood. Denied connections do not extend the
window. A monotonic clock regression is treated as a denial rather than guessed
away.

The service records `GH-SVC-1003` only for the first rate-limit activation in a
run and includes the saturated `rate_limited_connections` count in its final
event. Failure to write the first summary event stops admission through the
existing fail-closed audit path. Individual rejected connections are not
journaled.

## Consequences

- Connection churn cannot drive unbounded protocol parsing or per-request audit
  writes.
- Limiter memory is bounded by configuration and never grows with denials.
- Legitimate clients may burst up to the configured capacity and resume as each
  prior admission leaves the sliding window.
- The limit is global to one listener. A client with socket reachability can
  temporarily consume the shared budget and delay another legitimate client.
- Restarting the listener resets its in-memory window; startup and process
  controls remain responsible for restart-loop containment.

## Security impact

The limiter is defense in depth behind filesystem permissions and kernel peer
authentication. It reduces CPU and audit-capacity amplification but does not
replace correct socket ownership, peer authorization, journal rotation, or OS
resource limits. Messages and events contain neither peer identifiers, socket
paths, request bodies, nor timing details that reveal individual activity.

The first durable summary proves that limiting occurred without creating an
attacker-controlled number of log entries. A forced process termination can
lose the final aggregate count, but not an already written first-activation
event.

## Operational impact

Operators should investigate `GH-SVC-1003` as either a misconfigured client,
aggressive polling, or attempted local resource abuse. The read-only bootstrap
uses the conservative built-in default and exposes no command-line override.
Changing the default later requires workload evidence and regression tests.

Portable tests verify boundary bursts, exact expiry, retry calculation, reset,
invalid configuration, clock regression, service classification, single-event
auditing, and final aggregation. Native OpenBSD socket-pressure tests remain
required before production use.

## Alternatives considered

- Relying on serial admission was rejected because it bounds concurrency, not
  the number of quickly completed sessions.
- Auditing every denial was rejected because it preserves journal-amplification
  risk.
- A fixed wall-clock window was rejected because clock adjustment and boundary
  bursts weaken predictable enforcement.
- Sleeping before accepting any connection was rejected because idle service
  responsiveness should remain governed by the ordinary accept timeout.
- Per-peer buckets were deferred because the current bootstrap authorizes one
  exact API identity; a future multi-role protocol must revisit fairness before
  broadening socket access.
