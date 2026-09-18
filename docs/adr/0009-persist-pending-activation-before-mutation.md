# ADR-0009: Persist pending activation before PF mutation

- Status: accepted
- Date: 2026-09-18

## Context

An in-process activation coordinator can roll back ordinary errors, but it
cannot act after a crash, forced restart, or power interruption. If the process
dies after `pfctl -f` and before commit, the new ruleset may remain active while
the controller has forgotten which immutable revision must be restored.

Multiple controller processes must also not start independent activation
transactions against the same last-known-good base.

## Decision

Before the first possible PF mutation, Gatehold creates exactly one private,
durable `pending-activation` record. Creation uses a fully written and
synchronized temporary file followed by an atomic same-directory hard link, so
concurrent creators cannot replace one another and a partial record never
becomes authoritative.

The versioned record contains only:

- a constrained operation ID;
- the target immutable revision;
- the rollback immutable revision;
- one monotonic transaction phase.

Allowed phases are `prepared_for_load`, `target_loaded`, `verified`,
`awaiting_confirmation`, `committing`, and `committed`. Transitions may advance
only one step. Every replacement is written to a new private file, synchronized,
atomically renamed, and followed by directory synchronization.

The record has two roles:

1. its existence is a cross-process conflict guard for new activations;
2. it is the recovery instruction after controller startup.

Recovery treats every phase before `committed` as uncertain and revalidates and
reloads the recorded rollback revision. A `committed` record is cleared only
when the last-known-good marker agrees with its target revision. Missing,
malformed, unsafe, or inconsistent records are never guessed or automatically
overwritten.

The activation service clears the record after successful rollback or commit.
If post-commit cleanup fails, the committed record remains safe for idempotent
startup cleanup.

## Consequences

- A controller restart can deterministically recover an interrupted
  activation.
- An uncommitted ruleset is never accepted merely because the process died.
- Concurrent controller instances cannot both begin a new transaction.
- The activation root becomes part of the trusted controller-owned filesystem
  boundary.
- Startup must invoke recovery before accepting activation requests.
- The record is intentionally small and strict; it is not a general event log.

## Security impact

The transaction root must be absolute, owned by the controller identity, and not
writable by group or others. The record must be a private regular file and is
opened without following symbolic links. Operation IDs cannot contain path or
line-control characters.

The record is not cryptographically signed. A compromised controller identity
or root can still alter it. Gatehold therefore refuses malformed content and
requires consistency with immutable revisions and the last-known-good marker,
but cryptographic tamper evidence remains future hardening.

## Alternatives considered

- Keeping pending state only in memory was rejected because it cannot survive
  controller or host restart.
- Inferring rollback from the last journal lines was rejected because the audit
  journal is append-only evidence, not an atomic transaction state store.
- Overwriting a single record in place was rejected because interruption can
  leave a truncated or mixed record.
- Automatically deleting malformed records was rejected because that destroys
  the only evidence of an uncertain privileged mutation.
- A process-local mutex alone was rejected because it does not coordinate
  multiple controller processes.
