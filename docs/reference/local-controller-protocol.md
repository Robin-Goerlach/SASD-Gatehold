# Local controller protocol

Status: **experimental session API; serial listener available, no daemon yet**

The version 1 local protocol carries one narrowly scoped request over an
already-connected Unix-domain stream socket. `ControllerProtocolSession` verifies
the kernel peer identity, audits access, parses one bounded frame, dispatches
through `PrivilegedPfController`, writes one response, and returns. The caller
owns and closes the socket.

## Peer identity

| Platform | Credential source |
|---|---|
| OpenBSD | `getpeereid(3)` effective UID and GID |
| Linux CI | `getsockopt(SO_PEERCRED)` |
| Other platforms | Fail closed as unavailable |

`PeerCredentialPolicy` always requires an exact UID and can additionally
require an exact GID. Credentials are read before any request byte is parsed.
The accepted identity must then be durably journaled; audit failure prevents
dispatch.

This follows OpenBSD's documented
[`getpeereid(3)`](https://man.openbsd.org/getpeereid.3) contract for connected
Unix `SOCK_STREAM` or `SOCK_SEQPACKET` sockets.

## Transport frame

Every request and response is:

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 4 bytes | Unsigned payload length, big-endian |
| 4 | 1–4096 bytes | UTF-8-compatible ASCII protocol payload |

Zero length, length above 4096, truncation, missing final newline, carriage
returns, NUL bytes, unknown fields, reordered fields, and extra lines are
rejected. Input and response transfer each receive a separate caller-supplied
I/O deadline no longer than 60 seconds.

One connection contains exactly one request and one response. The listener must
close it afterward; pipelining is not supported.

## Status request

```text
gatehold-controller-v1
request_id=status-42
operation=status
```

`request_id` is 1–128 ASCII letters, digits, `-`, `_`, `.`, or `:`. The response
contains the current lifecycle state without starting the controller or changing
PF.

## Activation request

```text
gatehold-controller-v1
request_id=request-activate-42
operation=activate
operation_id=activate-revision-42
revision=42
authorization_reference=approval-reference-42
probe_timeout_ms=5000
confirmation_timeout_ms=60000
```

Rules:

- identifiers use the same constrained alphabet as `request_id`;
- `revision` is a non-zero unsigned 64-bit integer;
- `probe_timeout_ms` is 100–60000;
- `confirmation_timeout_ms` is 1000–600000;
- no field selects an executable, file, probe, endpoint, authorizer, or
  confirmation provider.

The authorization reference is passed to the trusted authorizer. It is not
included in protocol audit events or responses.

## Response

```text
gatehold-controller-v1
request_id=request-activate-42
result=completed
controller_state=ready
event_id=GH-ACT-0007
message=Activation request completed.
activation_status=committed
```

Status responses omit `activation_status`. Protocol `result=completed` means the
request was dispatched and a terminal result is present; it does not imply that
activation committed. The `activation_status` and stable `event_id` carry that
meaning. `result=rejected` means the request was valid but policy or controller
state prevented dispatch. `result=error` denotes protocol/audit failure.

Responses deliberately contain generic messages. Native diagnostics,
authorization references, executable output, filesystem paths, and probe targets
remain outside the wire response.

## Stable session events

| Event ID | Meaning |
|---|---|
| `GH-IPC-0001` | Kernel peer credentials authenticated and audited |
| `GH-IPC-0002` | Status request audited before dispatch |
| `GH-IPC-0003` | Activation request audited before dispatch |
| `GH-IPC-1001` | Peer UID/GID denied |
| `GH-IPC-1002` | Frame or request malformed, truncated, or oversized |
| `GH-IPC-1003` | Protocol version or operation unsupported |
| `GH-IPC-2001` | Kernel peer credentials unavailable |
| `GH-IPC-2002` | Input deadline expired |
| `GH-IPC-2003` | Socket read or response write failed |
| `GH-IPC-2004` | Authentication or dispatch intent could not be audited |

Audit attributes contain only peer UID/GID, request ID after validation,
operation type, and activation revision. They do not contain the authorization
reference.

## Response-loss semantics

The response channel is not part of the PF transaction boundary. If activation
is durably committed and response delivery then fails, the session returns
`io_error`/`GH-IPC-2003` locally but leaves the committed revision active. The
client must treat the outcome as unknown and reconcile it through a future
operation-status/audit query. Blind replay is unsafe and is not specified as an
idempotent recovery mechanism.

## Current boundary

The parser, peer credential policy, framing, deadlines, audit gate, and lifecycle
dispatch are implemented and failure-injection tested with `socketpair()`. A
separate serial listener can securely own a filesystem socket and dispatch one
connection at a time, and `ControllerService` owns recovery-first repeated
admission. No daemon process, signal bridge, API service account, `pledge`, or
`unveil` policy exists yet. The library therefore does not expose a production
privileged service. See the
[listener reference](local-controller-listener.md).
