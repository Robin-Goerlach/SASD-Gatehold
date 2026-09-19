# ADR-0018: Exclude concurrent daemon recovery

- Status: accepted
- Date: 2026-09-19

## Context

Filesystem preflight prevents a daemon from starting with an already occupied
socket path, but socket creation happens only after pending-transaction
recovery. Two processes starting at nearly the same time could both complete
preflight while the socket path was absent and then enter recovery concurrently.
The pending record serializes new activation transactions; it is not an
ownership primitive for controller startup or recovery.

Concurrent recovery is unacceptable because it can duplicate native PF loads,
produce contradictory audit sequences, or let one process observe state while
the other is changing it. Process exclusivity must therefore be established
before any recovery-capable controller object is constructed.

## Decision

After successful filesystem preflight, `gateholdd` acquires a nonblocking
exclusive `flock()` on the fixed `.gateholdd.lock` entry in the verified
transaction root. The lock is acquired before startup audit, signal handling,
controller construction, or pending-transaction recovery and is retained until
after the final shutdown audit.

The lock implementation:

- opens the transaction root with `O_DIRECTORY`, `O_NOFOLLOW`, and `O_CLOEXEC`;
- verifies that the root is owned by the effective UID and is not writable by
  group or other users;
- inspects the lock entry without following links;
- creates or opens it with `openat()`, `O_NOFOLLOW`, and mode `0600`;
- requires a regular file owned by the effective UID, with no group/other
  permissions and exactly one hard link;
- acquires `LOCK_EX|LOCK_NB` and rejects contention immediately;
- compares the locked descriptor identity with the named entry; and
- owns the descriptor through a move-only RAII value.

The lock file is persistent and contains no PID or other data. Gatehold neither
unlinks nor rewrites it during normal operation. Kernel descriptor ownership,
not file contents, represents the live lease. `O_CLOEXEC` prevents accidental
inheritance into executed helper programs.

## Consequences

- At most one correctly operating daemon can recover or serve a given
  transaction root at a time.
- A competing start fails immediately with exit status `3` before recovery or
  listener creation.
- Normal shutdown, startup failure, and process death release ownership when the
  descriptor closes; no stale PID parsing or lock-file removal is required.
- Multiple independent Gatehold instances remain possible when they use
  separate transaction roots and the other required trust roots.
- Installation and backup tooling must preserve `.gateholdd.lock` as a private
  controller-owned regular file when it already exists.

## Security impact

Successful acquisition is audited as `GH-DMN-0004`. Contention uses
`GH-DMN-1005`, an unsafe lock entry uses `GH-DMN-1006`, and indeterminate I/O
uses `GH-DMN-2003`. Rejections are written to the already verified journal with
`startup_gate=process-lock`; messages contain no configured path, PID, or lock
holder metadata.

The lock protects cooperating processes. Root or an attacker controlling the
daemon UID and transaction directory can unlink or replace the named entry and
is outside this boundary. Preflight, descriptor identity checks, private
directory permissions, and component-local validation remain necessary.

## Operational impact

Operators must treat `GH-DMN-1005` as evidence that another instance owns the
same transaction root, not as permission to remove the lock file. Service state
and the existing process should be inspected first. Because the file itself is
not the lease, deleting it can defeat exclusivity while a daemon is running.

No wait or retry occurs inside the privileged process. An OpenBSD supervisor may
apply a bounded restart policy, while configuration errors and persistent
contention remain visible failures.

## Alternatives considered

- Using only socket bind as the ownership gate was rejected because bind occurs
  after recovery.
- Storing and probing a PID was rejected because PID reuse, namespaces, and
  stale files make liveness inference unsafe.
- Removing a lock file after crashes was rejected because `flock()` is released
  by the kernel and the persistent inode needs no cleanup.
- Blocking indefinitely for the lock was rejected because supervisor-visible,
  fail-fast startup is easier to diagnose and bound.
- Using the pending-activation record as a lock was rejected because recovery
  must also run when no pending record exists.
