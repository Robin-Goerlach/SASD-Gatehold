# ADR-0019: Constrain the daemon with an OpenBSD process sandbox

- Status: accepted
- Date: 2026-09-19

## Context

`gateholdd` is a long-running privileged process that reads immutable revisions,
writes audit and transaction state, owns a local Unix socket, and invokes the
fixed `/sbin/pfctl` helper during startup recovery. Filesystem permissions and a
narrow protocol reduce exposure, but a memory-safety or logic defect would
otherwise retain the process identity's complete system-call and filesystem
authority.

The sandbox must be installed before the signal thread, controller construction,
pending-transaction recovery, or listener admission. It must still leave the
already acquired process lock releasable and the journal writable when a later
startup step fails.

## Decision

After filesystem preflight, process-lock acquisition, and durable startup audit,
the OpenBSD build installs this locked `unveil()` view in order:

| Path role | Permission |
|---|---|
| Audit root | `rwc` |
| Immutable revision root | `r` |
| Transaction root | `rwc` |
| Controller-socket parent | `rwc` |
| `/sbin/pfctl` | `x` |
| `/dev/pf` | `rw` |

It then calls `unveil(NULL, NULL)` and pledges exactly:

```text
stdio rpath wpath cpath fattr flock unix proc exec
```

The promises cover existing descriptor work and timers, bounded filesystem
access inside the unveiled view, socket permission changes, journal locks, local
Unix sockets, and the shell-free `fork()`/`execve()` helper runner. No `inet`,
DNS, route, device-creation, user-database, or broad device promise is granted.

The parent deliberately supplies no `execpromises` yet. OpenBSD therefore starts
the executed `pfctl` image without inherited pledge restrictions, while the
locked unveiled filesystem view remains inherited. Guessing a smaller `pfctl`
promise set before native recovery tests could terminate a firewall recovery at
the worst possible time. A separately constrained helper process remains a
future hardening step.

Every partial `unveil`, lock, or `pledge` failure rejects OpenBSD startup. The
portable adapter reports the sandbox as unsupported without pretending that it
was enforced; non-OpenBSD executables remain development/test artifacts only.

## Consequences

- The long-running OpenBSD parent cannot see paths outside six explicit rules.
- The revision store is read-only at the kernel sandbox boundary.
- The daemon cannot create Internet sockets even if a later defect reaches the
  dormant TCP-probe implementation.
- Audit, transaction recovery, Unix listener lifecycle, and fixed-path `pfctl`
  execution retain the operations they require.
- Adding a runtime path or syscall category now requires an explicit policy,
  tests, threat-model update, and native OpenBSD verification.
- `pfctl` is filesystem-constrained but not yet pledge-constrained after exec.

## Security impact

The policy closes broad filesystem and syscall authority after the startup
trust roots have been checked. Policy validation rejects altered permissions,
duplicate or unsafe paths, and changed promises before making a platform call.
Failures use path-free messages and stable `GH-SBX-*` events so configured paths
do not leak to standard error or the journal.

Sandboxing is defense in depth. It does not protect against root, a compromised
kernel, malicious behavior entirely inside the unveiled roots, or misuse of the
allowed `pfctl` operation.

## Operational impact

OpenBSD startup treats any `GH-SBX-2001`, `GH-SBX-2002`, or `GH-SBX-2003` event
as fatal. `GH-SBX-0001` proves policy installation and locking. `GH-SBX-1001`
means the binary is running on a non-target platform without enforcement and
must not be deployed as a privileged service.

Portable tests inject the platform boundary and verify exact ordering, every
partial failure, policy rejection, locked unveil state, absence of child
promises, and non-disclosure. Native OpenBSD daemon recovery and PF tests are
still required before production use.

## Alternatives considered

- Filesystem permissions alone were rejected because they do not restrict the
  privileged process from opening unrelated system paths.
- Applying only `pledge()` was rejected because allowed path operations would
  remain system-wide.
- Supplying an unverified `pfctl` exec-promise set was rejected because an
  incomplete set could break fail-safe recovery.
- Unveiling all system library directories was rejected; official OpenBSD base
  utilities demonstrate execution with only the target executable unveiled.
- Applying the sandbox after recovery was rejected because recovery executes
  native privileged work and belongs inside the boundary.
