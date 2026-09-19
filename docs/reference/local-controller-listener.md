# Local controller listener

Status: **experimental serial listener API; service loop available, no daemon
entry point yet**

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
| `listen_backlog` | 1–64, default 8 | Bound the kernel pending queue |
| Accept timeout | 1–60000 ms per `serve_one()` | Bound waiting for a connection |
| Session timeout | 1–60000 ms per `serve_one()` | Bound protocol input and response transfer |

The parent must already exist. It must be a non-symlink directory owned by the
effective listener UID, not group-writable, and inaccessible to other users.
For a group-accessible socket, deployment can use a trusted set-group-ID parent
with the intended API group and mode `2750`; the listener itself accepts only
`0600` or `0660` for the socket.

## Startup order

1. Validate path, mode, and backlog.
2. Durably append `GH-LSN-0001`.
3. Verify and open the trusted parent directory.
4. Refuse any existing final path component.
5. Create a non-blocking, close-on-exec Unix stream socket.
6. Bind without a preceding unlink.
7. Verify type, owner, mode, device, and inode.
8. Start listening with the bounded backlog.
9. Durably append `GH-LSN-0002`.

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
the listener. Supervisor integration, API account provisioning, journal
rotation, credential reduction, and native sandbox/listener verification remain
future work. OpenBSD bind, permission, inheritance, and cleanup behavior must be
verified in the disposable lab before production use.
