# ADR-0012: Authenticate and bound local controller sessions

- Status: accepted
- Date: 2026-09-19

## Context

The unprivileged API must eventually request narrowly scoped work from a small
privileged daemon. A Unix-domain socket is local, but locality alone is not
authorization. Stream boundaries are not message boundaries, clients can stall
mid-request, and a compromised local process can send oversized, malformed, or
replayed input. The protocol must also preserve the controller rule that startup
recovery precedes every activation.

## Decision

Gatehold introduces a session layer for one already-connected Unix-domain
`SOCK_STREAM` socket. Before reading request content, the session obtains the
kernel-reported effective peer UID and GID. OpenBSD uses `getpeereid()`; Linux
tests use `SO_PEERCRED`. An exact configured UID is mandatory and an exact GID
can be required in addition.

Accepted authentication is durably audited before request parsing. If that
append fails, the session returns an error and dispatches nothing. A denied peer
is never parsed. Authorization references are transported only inside a valid
activation request and are neither echoed in the response nor copied into the
protocol audit event.

Version 1 uses a four-byte unsigned big-endian payload length followed by at
most 4096 bytes. The newline-terminated payload has a fixed version line, fixed
field order, no unknown fields, and constrained identifiers. One connection
carries exactly one request and one response.

The initial operations are:

- `status`, which returns the lifecycle controller state;
- `activate`, which supplies only operation/revision/authorization correlation
  and bounded probe/confirmation deadlines.

Requests cannot choose executables, paths, probes, probe targets, authorizer
implementations, or confirmation providers. Activation always enters through
`PrivilegedPfController::activate()`, so the startup recovery gate and degraded
states remain authoritative.

Input and output each use a separate positive deadline of at most 60 seconds.
Sockets are changed to non-blocking and close-on-exec mode. Partial and oversized
frames are rejected. Response writes suppress `SIGPIPE` where the platform
requires it.

## Consequences

- Kernel credentials authenticate the local process identity without trusting a
  request field.
- Exact framing prevents stream fragmentation, coalescing, and allocation size
  from changing parser behavior.
- Audit failure blocks dispatch before the privileged operation begins.
- The same immutable session object can serve independent accepted sockets
  concurrently; the lifecycle controller still serializes mutations.
- One-request connections simplify state and parser review at the cost of more
  connection and authentication events.

If activation commits but the client closes before receiving the response, the
session reports an I/O failure but does not roll back a durably confirmed
configuration. A future client must reconcile that ambiguous response through
operation/audit lookup instead of blindly replaying the request.

## Security impact

Peer identity and protocol access are separate from per-operation authorization.
Compromise of the allowlisted API identity still does not turn a goal into
authorization: the trusted `ActivationAuthorizer` must approve the supplied
reference and target.

The fixed schema excludes generic command execution and probe selection. Length,
identifier, numeric, and timeout validation occurs before controller dispatch.
Protocol events use stable `GH-IPC-*` identifiers and never contain the
authorization reference.

## Operational impact

The future listener must live below an absolute controller-owned directory with
restrictive permissions, create a private socket, bound concurrent sessions,
and close each connection after `serve()` returns. Its configured API UID/GID
must match the service account actually connecting.

Repeated authenticated connections consume audit capacity. Listener admission
limits, rate controls, journal rotation, and operation-result lookup remain
required before production exposure.

## Alternatives considered

- Trusting filesystem socket permissions alone was rejected because peer
  credentials provide an independent kernel identity check.
- Sending UID/GID inside the request was rejected because the client controls
  those fields.
- Unbounded JSON was rejected because a full parser and flexible schema enlarge
  the privileged attack surface.
- A generic RPC or command operation was rejected because it would bypass the
  narrow capability boundary.
- Multiple requests per connection were deferred because they add session state,
  resynchronization, and resource-accounting complexity.
- Rolling back when the response cannot be delivered was rejected because the
  operation may already be durably confirmed and response transport is not a
  safe configuration signal.
