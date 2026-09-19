# ADR-0013: Bind local controller sockets without replacement

- Status: accepted
- Date: 2026-09-19

## Context

The authenticated controller protocol previously accepted only an already
connected descriptor. A future privileged service needs a filesystem Unix
socket, but creating and removing that path introduces a separate trust
boundary. Blindly unlinking a stale-looking entry can delete an administrator's
file or another service's socket. A writable or symlinked parent can redirect
binding and cleanup. Unbounded admission can also exhaust descriptors, threads,
or the durable audit journal.

## Decision

Gatehold adds `LocalControllerListener`, an experimental library component that
binds one Unix-domain `SOCK_STREAM` endpoint and passes one accepted connection
at a time to `ControllerProtocolSession`.

The configured socket path must:

- be absolute, lexically normalized, and below a canonical non-symlink parent;
- fit the platform `sockaddr_un::sun_path` field;
- have a final component other than an empty name, `.` or `..`;
- not already exist as any filesystem object.

The immediate parent directory must be owned by the listener's effective UID,
must not be group-writable, and must have no permissions for other users. It is
opened with `O_DIRECTORY`, `O_NOFOLLOW`, and `O_CLOEXEC`; the opened device and
inode must match the earlier `lstat()` result.

The listener never unlinks an entry before `bind()`. After binding, it verifies
that the entry is a socket owned by the effective UID and restricts its mode to
exactly `0600` or `0660`. The listen backlog is limited to 1–64. Listener and
accepted descriptors are non-blocking and close-on-exec; OpenBSD and Linux use
`accept4()` so accepted flags are atomic.

Startup intent must be durably audited before socket creation. Readiness must be
audited before `start()` returns and before the caller can enter `serve_one()`.
If readiness audit fails, the listening descriptor and owned socket entry are
removed without dispatching a request.

One `serve_one()` call may be active. A concurrent admission or stop request is
rejected with `GH-LSN-1004`. Both the accept deadline and the protocol-session
deadline are positive and at most 60 seconds. Idle accept expiry is returned but
not journaled, because a supervisor loop could otherwise consume the audit
capacity without any client activity.

For cleanup, the listener retains the opened parent descriptor plus the device
and inode of its bound socket. It calls `unlinkat()` only if the current entry is
still the same socket. A substituted file, symlink, or socket is preserved and
reported as `GH-LSN-2004`.

## Consequences

- Existing filesystem entries are never treated as disposable stale sockets.
- A trusted parent and inode-bound cleanup reduce pathname replacement risk.
- Serial admission creates a simple, explicit concurrency bound of one.
- A caller must provide the outer stop-aware accept loop; the library does not
  yet constitute a daemon.
- Mode `0660` relies on deployment assigning the intended group through the
  trusted parent directory. Kernel peer UID/GID verification remains mandatory
  even when filesystem permissions allow connection.

## Security impact

Socket filesystem permissions are defense in depth, not the authorization
decision. Every accepted connection still passes through the protocol's kernel
credential policy and per-operation authorizer. The request cannot choose the
socket path, permissions, backlog, peer policy, executable, or health probes.

Listener events contain only stable IDs, outcomes, backlog, and the selected
permission class. Absolute paths, authorization references, peer-controlled
payloads, and native error strings are not journaled.

## Operational impact

Packaging must create the runtime directory before startup with the controller
as owner, no group write permission, and no access for other users. Deployments
using `0660` should assign a dedicated API group to that directory and verify
the inherited socket group. An unexpected existing entry is an operator-visible
startup failure; Gatehold does not guess whether it is stale.

The portable listener test executes validation and audit failure cases even in
restricted sandboxes. A runtime that prohibits `socket(AF_UNIX, ...)` reports an
explicit skip for bind/listen/accept cases; normal Linux CI and the OpenBSD lab
must execute those cases.

## Alternatives considered

- Unlinking the configured path before every bind was rejected because it can
  delete an unrelated or attacker-substituted entry.
- Using `/tmp` directly was rejected because the immediate listener parent must
  be controller-owned and inaccessible to other users.
- A thread per accepted connection was deferred because it introduces an
  avoidable unbounded resource surface.
- Trusting socket mode without peer credentials was rejected because filesystem
  permissions and process identity are independent controls.
- Auditing every empty accept timeout was rejected because idle operation must
  not exhaust the finite journal.
