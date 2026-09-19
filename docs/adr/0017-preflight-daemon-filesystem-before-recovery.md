# ADR-0017: Preflight daemon filesystems before recovery

- Status: accepted
- Date: 2026-09-19

## Context

The daemon's journal, revision store, pending-transaction store, and local
socket listener each validate their own filesystem boundary when first used.
That remains necessary, but it allowed startup to enter signal handling and
pending-transaction recovery before all four roots had been checked together.
In particular, an already occupied socket path could be discovered only after
recovery. A second daemon invocation must not touch PF recovery state before it
knows that its complete configured filesystem surface is admissible.

## Decision

`gateholdd` performs one fail-closed filesystem preflight after argument and
identity validation, but before its startup event, signal bridge, controller
construction, or recovery. It checks, in fixed order:

1. the operation-journal root;
2. the immutable-revision root;
3. the pending-transaction root;
4. the controller-socket parent and target path.

Every directory must already exist, resolve canonically to the exact configured
path, be a directory owned by the daemon's effective UID, and reject writes by
group or other users. The socket parent additionally permits no access by other
users and no group write. Mode `0660` requires its GID to match the daemon's
effective and configured GID and requires group traversal. The socket target
must not exist; the daemon never removes an entry during startup.

The implementation compares `lstat()` identity with an
`O_DIRECTORY|O_NOFOLLOW` descriptor before considering a directory checked.
Individual stores and the listener retain their own validation because
preflight does not eliminate time-of-check/time-of-use races.

## Consequences

- Recovery cannot begin with a missing, aliased, misowned, writable, or
  otherwise inconsistent configured root.
- An existing socket entry rejects startup before recovery, including a socket
  that probably belongs to another daemon.
- Provisioning must create and permission every directory before starting the
  service.
- The journal is checked first. Failures in later roots are audited there;
  failure of the journal root itself is reported only on standard error because
  no trusted durable sink exists yet.
- Preflight alone leaves a simultaneous-start race before listener bind. The
  process lock accepted in ADR-0018 closes that race before recovery.

## Security impact

Stable events distinguish accepted preflight (`GH-DMN-0003`), rejected
directories (`GH-DMN-1003`), occupied socket targets (`GH-DMN-1004`), and
filesystem I/O uncertainty (`GH-DMN-2002`). Diagnostics name only the directory
role in a structured attribute and never include configured paths. Any
uncertainty fails closed.

This check narrows startup exposure; it is not a sandbox and does not protect
against root or a compromised daemon identity changing a path after preflight.
Descriptor-relative store operations and listener identity checks remain the
authoritative use-time boundaries.

## Operational impact

Filesystem-preflight rejection exits with status `3`. Operators should inspect
the event ID and `directory_role` attribute in the journal, correct
provisioning or resolve the occupied socket deliberately, and retry. Gatehold
does not unlink stale-looking entries automatically.

## Alternatives considered

- Relying only on component-local validation was rejected because recovery
  would precede listener-path validation.
- Removing an existing socket automatically was rejected because pathname
  presence does not prove ownership or staleness.
- Logging raw failed paths was rejected because stable roles are sufficient
  for diagnosis and disclose less deployment information.
