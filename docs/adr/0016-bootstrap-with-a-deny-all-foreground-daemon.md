# ADR-0016: Bootstrap with a deny-all foreground daemon

- Status: accepted
- Date: 2026-09-19

## Context

The recovery-gated controller, authenticated listener, service loop, and POSIX
signal bridge existed as separate library components. Without one executable,
their startup and shutdown ordering remained untested. Enabling real activation
at this boundary would be premature: Gatehold does not yet have a production
authorization provider, confirmation channel, or appliance health policy.

## Decision

Gatehold adds `gateholdd`, a foreground privileged-controller process with one
explicit command: `serve-read-only`. It wires components in this order:

1. strictly parse paths and the allowed numeric peer identity;
2. append daemon startup intent to the durable journal;
3. block and synchronously monitor `SIGINT` and `SIGTERM`;
4. construct the revision and pending-transaction stores;
5. install a deny-all authorizer, unavailable confirmation gate, and fail-closed
   health probe;
6. run mandatory pending-activation recovery;
7. expose the authenticated local listener only after recovery;
8. stop admission cooperatively, remove the owned socket, join signal handling,
   and audit daemon shutdown.

The process deliberately stays in the foreground for supervision by OpenBSD
`rc.d`. It does not fork, create a PID file, select arbitrary executables, or
accept relative paths. Journal, revision, transaction, and socket directories
must be normalized, absolute, pairwise non-overlapping trust roots. The socket
directory must also be separate from all durable stores.

The bootstrap policy rejects every new activation before revision lookup,
native validation, transaction creation, PF loading, health verification, or
confirmation. A syntactically valid activation request is still audited as
denied. Status requests remain available.

Startup recovery is not passive. If a durable pending transaction exists, the
existing recovery policy may validate and restore its last-known-good PF
revision before the listener opens. “Read-only” therefore means no *new*
activation authorization; it does not disable required crash recovery.

## Consequences

- The implemented security components now have a real process owner and an
  end-to-end lifecycle.
- Operators can inspect recovered controller state through the authenticated
  local protocol without enabling configuration changes.
- Production activation remains impossible until a later explicit policy
  decision replaces all three fail-closed providers.
- Runtime directories and ownership must be provisioned before launch.
- Credential dropping, `rc.d`, per-identity fairness, constrained child-process
  promises, production configuration-file loading, and native verification of
  the later sandbox and rate-limit policies remain future hardening work.

## Security impact

Argument errors never echo option values. Peer identity is a numeric UID with
an optional exact GID. Without a GID, mode `0600` requires the allowed UID to be
the daemon's effective UID. With a GID, mode `0660` requires that GID to be the
daemon's effective group; the kernel peer policy still requires both the exact
configured UID and GID. Storage and socket paths cannot alias or nest across
trust boundaries. No argument can replace the fixed `/sbin/pfctl` executable.

The denial policy is independently tested through `PfActivationService` with a
nonexistent validator/loader path. The result must contain no native validation,
load, transaction, rollback, or secret authorization reference.

## Operational impact

Exit status `0` means cooperative shutdown. `2` denotes invalid arguments, `3`
startup failure, `4` controller-service failure, and `5` cleanup or final audit
failure. Runtime diagnostics use stable `GH-DMN-*` and nested component event
IDs. The journal remains authoritative; standard error contains only generic
event ID and message pairs.

Supervisors must send `SIGTERM` and allow in-flight recovery or a protocol
request to reach its bounded terminal state. A hard kill may leave pending state
for the next startup recovery.

## Alternatives considered

- Enabling activation with a hard-coded approval token was rejected because a
  token string is not a production authorization decision.
- Omitting activation from the protocol only in `main()` was rejected because
  the actual deny policy would not be independently testable.
- Daemonizing internally was rejected because OpenBSD service supervision
  should own process lifecycle.
- Accepting a configurable `pfctl` path was rejected because the privileged
  process must not turn configuration input into executable selection.
