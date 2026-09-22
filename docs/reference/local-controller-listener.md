# Local controller listener

Status: **experimental rate-limited serial listener used by the read-only daemon**

`LocalControllerListener` owns a filesystem Unix-domain stream socket and
connects it to `ControllerProtocolSession`. It exposes explicit `start()`,
`serve_one()`, and `stop()` operations. The listener does not start the
controller lifecycle, fork, create worker threads, or run an infinite accept
loop.

## Configuration

| Setting | Accepted values | Purpose |
|---|---|---|
| `socket_path` | Absolute canonical path fitting `sun_path` | Select the endpoint |
| `socket_mode` | Exactly `0600` or `0660` | Restrict filesystem connection access |
| `socket_group_id` | Absent with `0600`; exact GID with `0660` | Select the delegated socket group |
| `listen_backlog` | 1–64, default 8 | Bound the kernel pending queue |
| Admission limit | 1–1024, default 30 | Bound sessions entering the protocol per window |
| Admission window | 100–3600000 ms, default 60000 ms | Sliding monotonic rate window |
| Accept timeout | 1–60000 ms per `serve_one()` | Bound waiting for a connection |
| Session timeout | 1–60000 ms per `serve_one()` | Bound protocol input and response transfer |

The parent must already exist. It must be a non-symlink directory owned by the
effective listener UID, not group-writable, and inaccessible to other users.
For a group-accessible socket, deployment uses a trusted parent owned by the
daemon, assigned to the intended API group, and typically mode `0750`. The
listener explicitly assigns the socket to `socket_group_id`; it does not rely
on set-group-ID inheritance. The daemon preflight requires the configured group
on the parent so the API can traverse it.

## Startup order

1. Validate path, mode, backlog, and admission-rate bounds.
2. Durably append `GH-LSN-0001`.
3. Verify and open the trusted parent directory.
4. Refuse any existing final path component.
5. Create a non-blocking, close-on-exec Unix stream socket.
6. Bind without a preceding unlink.
7. Verify the new entry's type, owner, device, and inode.
8. For mode `0660`, assign the exact configured group without following links.
9. Set the exact mode and re-verify type, owner, group, mode, device, and inode.
10. Start listening with the bounded backlog.
11. Durably append `GH-LSN-0002`.

If the final readiness append fails, startup closes the descriptor and removes
only the socket inode it just created. `start()` is idempotent after success.

## Admission and dispatch

`serve_one()` admits one connection, gives it to
`ControllerProtocolSession::serve()`, closes it, and returns the complete
protocol result. `LocalListenerStatus::session_completed` means the connection
reached a terminal protocol result; callers must inspect the nested result to
distinguish success, peer rejection, invalid input, timeout, audit failure, and
I/O failure.

Only one `serve_one()` invocation may be active. A second call returns `busy`
without accepting a connection. `stop()` also returns `busy` until the active
admission completes. An accept timeout leaves the listener active and is not
written to the durable journal.

After accepting a socket, a monotonic sliding-window limiter runs before peer
inspection, frame parsing, request audit, or dispatch. The 31st connection in a
default 60-second window is closed and returned as `rate_limited`; denied
connections do not consume more window capacity. Rejection waits for at most
the current accept timeout to prevent a CPU-intensive accept/close loop.

The listener does not journal individual denials. `ControllerService` durably
records only the first rate-limit activation per run and summarizes the total at
shutdown. This preserves evidence without allowing connection churn to amplify
audit writes.

## Safe shutdown

The listener records its socket device and inode after binding. Shutdown closes
the listening descriptor and uses the still-open parent directory descriptor to
compare the current entry with that identity. It unlinks only an exact socket
match. An already absent name is clean; if the name has been replaced, the
replacement is preserved and shutdown returns `cleanup_failed`.

The destructor performs the same identity-checked cleanup as a safety net, but
production callers should use `stop()` so shutdown success or audit failure is
observable.

## Stable listener events

| Event ID | Meaning |
|---|---|
| `GH-LSN-0001` | Listener startup intent durably recorded |
| `GH-LSN-0002` | Secured socket is listening |
| `GH-LSN-0003` | Listener stopped and owned path removed |
| `GH-LSN-1001` | Path, mode, backlog, timeout, or lifecycle use invalid |
| `GH-LSN-1002` | Parent directory unsafe or changed identity |
| `GH-LSN-1003` | Final socket path already occupied |
| `GH-LSN-1004` | Concurrent admission or stop rejected as busy |
| `GH-LSN-1005` | Accept deadline expired; returned but not journaled |
| `GH-LSN-1006` | Connection closed before protocol work by the admission limit |
| `GH-LSN-2001` | Socket creation, binding, securing, or listen failed |
| `GH-LSN-2002` | Startup, readiness, or shutdown audit failed |
| `GH-LSN-2003` | Pending connection could not be accepted |
| `GH-LSN-2004` | Owned socket path could not be removed safely |

Journal records never include the configured socket path or client request
content. Authentication and request-level events remain the responsibility of
the `GH-IPC-*` protocol layer.

## Current boundary

The listener remains a library component. A stop-aware `ControllerService` loop
owns repeated admission and mandatory recovery ordering, while `gateholdd`
provides process signals and installs the OpenBSD sandbox before constructing
the listener. An experimental OpenBSD `rc.d` wrapper now supervises that
foreground process. A guarded lifecycle harness now checks OpenBSD bind, group
delegation, permissions, and cooperative cleanup, but native evidence has not
yet been recorded. API account provisioning, journal rotation, credential
reduction, and native sandbox verification remain future work.
