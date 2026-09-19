# POSIX signal stop bridge

Status: **experimental library component; daemon integration pending**

`PosixSignalStopBridge` translates process `SIGINT` and `SIGTERM` delivery into
the `std::stop_token` consumed by `ControllerService`. It uses a synchronous
`sigwait()` thread and installs no asynchronous signal handler.

## Required lifecycle

1. Construct the audit journal and bridge on the daemon's main thread.
2. Call `start()` before creating the controller service or any other threads.
3. Pass `stop_token()` to `ControllerService::run()`.
4. After the service returns, call `stop()` on the same main thread.

`start()` blocks `SIGINT` and `SIGTERM` on the caller. Threads created afterward
inherit that mask. Starting after other threads is unsupported because a prior
thread could receive a termination signal outside the synchronous waiter.

Only one bridge may be active in a process, and each instance is one-shot.
`stop()` joins the waiter and restores the starting thread's exact earlier
mask. A wrong-thread `stop()` returns `GH-SIG-1005` and makes no changes. The
bridge must also be destroyed on its starting thread; another thread cannot
restore a POSIX signal mask on the starter's behalf.

## Stop behavior

The first received termination signal:

- stores its numeric identity for local inspection;
- requests the bridge stop source;
- appends `GH-SIG-0002` with only `SIGINT` or `SIGTERM` as an attribute;
- leaves the waiter alive to consume later termination signals until cleanup.

If the received-signal event cannot be appended, the stop request is still
made because suppressing supervisor termination would reduce availability.
`signal_event_audited()` exposes that audit failure to the process owner.

The bridge only requests cooperative stop. It does not interrupt an active
protocol request or firewall transaction and does not impose a hard shutdown
deadline.

## Stable signal events

| Event ID | Meaning |
|---|---|
| `GH-SIG-0001` | Synchronous signal monitoring startup intent |
| `GH-SIG-0002` | `SIGINT` or `SIGTERM` requested cooperative stop |
| `GH-SIG-0003` | Signal waiter joined and prior mask restored |
| `GH-SIG-1001` | Instance is already active |
| `GH-SIG-1002` | One-shot instance has already stopped |
| `GH-SIG-1003` | Another bridge owns process signal consumption |
| `GH-SIG-1004` | Stop requested before start |
| `GH-SIG-1005` | Stop called from a thread other than the starter |
| `GH-SIG-2001` | Startup audit failed; signal mask was not changed |
| `GH-SIG-2002` | `SIGINT`/`SIGTERM` blocking failed |
| `GH-SIG-2003` | Signal-waiting thread creation failed |
| `GH-SIG-2004` | `sigwait()` failed |
| `GH-SIG-2005` | Waiting thread could not be woken for cleanup |
| `GH-SIG-2006` | Starting thread's prior signal mask was not restored |
| `GH-SIG-2007` | Cleanup completed but shutdown audit failed |

## Current boundary

Portable tests deliver real `SIGINT` and `SIGTERM` to the test process, verify
the stop token and journal, reject competing ownership and wrong-thread cleanup,
and compare mask state before and after use. Native daemon startup ordering and
supervisor behavior still require an OpenBSD integration test.
