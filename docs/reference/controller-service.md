# Controller service run loop

Status: **experimental run loop composed by the read-only daemon**

`ControllerService` owns the ordering between controller recovery, listener
startup, repeated serial admission, stop observation, and listener shutdown. It
does not itself daemonize, install signal handlers, change UID/GID, or apply a
sandbox. `gateholdd` supplies the process-level signal and sandbox boundaries
before constructing this service.

## Configuration

| Setting | Range | Default |
|---|---:|---:|
| Accept poll interval | 10–1000 ms | 250 ms |
| Protocol I/O timeout | 1–60000 ms | 5000 ms |
| Consecutive listener-error limit | 1–100 | 3 |

Invalid configuration returns `GH-SVC-1001` after mandatory controller recovery
but before listener startup. Only one `run()` call can be active for a service
instance.

## Startup and recovery

`run(stop_token)` first records service startup intent and always calls
`PrivilegedPfController::start()`. Pending activation recovery therefore occurs
before any listener admission. If the service intent audit failed, recovery is
still completed but the listener remains closed.

A stop token already requested on entry is checked after recovery. This permits
safe startup reconciliation without transiently exposing the socket.

Controller state and service availability are intentionally distinct:

| Controller state | Listener may run | Activation |
|---|---|---|
| `ready` | Yes | Allowed subject to authorization and safety workflow |
| `read_only` | Yes when listener/service audit remains healthy | Rejected |
| `blocked` | Yes for status diagnostics | Rejected |

In practice an audit-driven `read_only` state normally prevents the listener
from starting against the same unavailable journal.

## Run-loop classification

| Listener result | Service action |
|---|---|
| `session_completed` | Count session and nested failure; reset error streak |
| `accept_timed_out` | Count idle poll; reset listener-error streak; check stop token |
| `rate_limited` | Count rejection; audit only the first activation; reset error streak |
| Any other result | Count listener error; terminate at configured consecutive limit |

Protocol failure does not mean listener failure. A denied peer, malformed frame,
request timeout, or response loss has already reached a bounded terminal
protocol result and does not let a client consume the infrastructure-error
budget.

## Stop semantics

Stop is checked between `serve_one()` calls. Idle response is bounded by the
accept poll interval. An accepted protocol request is not interrupted: any
activation, confirmation, commit, or rollback finishes under its own deadlines
before the listener is closed.

After the loop, `stop()` must securely close and remove the listener-owned
socket. Cleanup failure becomes `shutdown_failed` even if the original reason
for leaving the loop was different. The final audit event includes saturated
counts for handled sessions, protocol failures, rate-limited connections, and
listener errors.

## Stable service events

| Event ID | Meaning |
|---|---|
| `GH-SVC-0001` | Service startup intent and recovery begin |
| `GH-SVC-0002` | Listener admission loop active |
| `GH-SVC-0003` | Listener closed and service stopped |
| `GH-SVC-1001` | Service timing or error-limit configuration invalid |
| `GH-SVC-1002` | Concurrent second run loop rejected |
| `GH-SVC-1003` | Admission rate limit activated; emitted once per service run |
| `GH-SVC-2001` | Startup intent audit failed after mandatory recovery |
| `GH-SVC-2002` | Listener startup failed |
| `GH-SVC-2003` | Consecutive listener-error limit reached |
| `GH-SVC-2004` | Listener shutdown or secure cleanup failed |
| `GH-SVC-2005` | Running or shutdown state could not be audited |

## Current boundary

The run loop is dependency-injection tested with scripted listener outcomes and
the real recovery-gated controller. The real listener remains separately tested.
The experimental `PosixSignalStopBridge` can now convert `SIGTERM`/`SIGINT` to
the run loop's stop token without an asynchronous handler. The experimental
`gateholdd serve-read-only` executable wires the components together with a
deny-all activation policy. It does not provision the API identity, drop
credentials, or integrate `rc.d`. The daemon now applies its OpenBSD sandbox
before constructing the run loop; native verification remains pending.
