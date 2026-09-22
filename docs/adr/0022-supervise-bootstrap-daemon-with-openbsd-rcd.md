# ADR-0022: Supervise the bootstrap daemon with OpenBSD rc.d

- Status: accepted
- Date: 2026-09-22

## Context

`gateholdd` deliberately remains in the foreground and converts `SIGTERM` into
a cooperative stop. A deployable OpenBSD service must integrate with the base
system's control framework without adding custom daemonization, PID files,
shell cleanup, or a competing supervisor.

OpenBSD `rc.subr(8)` runs an implemented `rc_configtest` before start and
restart. A configuration check cannot simply run the complete startup
preflight: during restart, the still-running daemon legitimately owns the
configured socket path. It also must not create a journal, acquire the process
lock, mutate PF, or remove an endpoint merely to answer whether configuration
is valid.

## Decision

Gatehold ships an experimental `packaging/openbsd/rc.d/gateholdd` definition
for isolated native labs. It:

- declares `/usr/local/sbin/gateholdd serve-read-only` as the mandatory daemon
  command;
- lets the default `rc.subr` start and stop functions manage the process;
- uses the mandatory `serve-read-only` command as a stable process expression,
  so changing site flags cannot hide an already running daemon from stop;
- sets `rc_bg=YES` because Gatehold itself stays in the foreground;
- redirects standard output and error through `daemon.info`;
- disables reload because the daemon has no safe reload operation;
- implements `rc_configtest` by invoking `gateholdd check-config` with the same
  site-controlled flags through `rc_exec`, preserving the configured user,
  login class, routing table, execution directory, and logger boundary;
- performs no custom PID, unlink, retry, or stale-socket logic.

`check-config` reuses the production argument and identity validators. It then
checks canonical directory paths, ownership, modes, group traversal, and stable
opened directory identities. It deliberately permits an occupied final socket
path. It does not write the durable audit journal because a configuration test
is side-effect-free and is not a privileged state transition.

Normal startup repeats identity and directory validation, additionally requires
the socket path to be absent, acquires the process lock, audits intent, installs
the sandbox, performs recovery, and only then admits local sessions.

The package layout places `gateholdd` in `/usr/local/sbin` and `gateholdctl` in
`/usr/local/bin`. The root controller retains PF authority. A separate disabled
`_gateholdapi` account receives only filesystem reachability to a mode `0660`
socket and must still pass exact kernel peer UID/GID authentication.

## Consequences

- OpenBSD operators can use `rcctl configtest`, `start`, `stop`, `restart`, and
  `check` through the native service framework.
- A restart does not fail merely because the current daemon socket exists.
- Configuration checking and startup readiness are explicit separate gates.
- Required flags remain site configuration in `rc.conf.local`; no privileged
  configuration-file parser is introduced by this milestone.
- Runtime directories and the API identity must still be provisioned outside
  the daemon.

## Security impact

The service script does not delete paths, evaluate a second custom command
language, accept a configurable executable, or run Gatehold as the API user.
Only root-controlled `rc.conf.local` supplies daemon flags. Parser errors and
configuration-check diagnostics remain path- and secret-free.

Allowing an occupied socket during `check-config` does not weaken startup:
`serve-read-only` still rejects every existing final path component before
recovery. An attacker able to change root-owned service flags, trust roots, or
the service script is outside this boundary.

## Operational impact

The packaging guide documents numeric identity resolution, exact directory
owners and modes, `rcctl` configuration, and lab-only limitations. Standard
error routed to syslog is diagnostic; the durable Gatehold journal remains the
authoritative security record.

The script, permissions, unsafe-token exclusions, documentation, parser,
side-effect-free configuration check, and occupied-socket distinction are
portable-tested. Native OpenBSD tests must still prove boot ordering, account
and `/var/run` lifecycle, `rcctl` behavior, logging, signal shutdown, crash
recovery, and socket-group delegation before packaging is production-ready.

## Alternatives considered

- Internal daemonization and a custom PID file were rejected because they
  duplicate `rc.subr` and complicate process identity.
- Removing an existing socket in the service script was rejected because it
  could unlink another process's live or attacker-substituted endpoint.
- Running full startup as a configuration test was rejected because it creates
  state and cannot safely coexist with a running daemon.
- Running the controller as `_gateholdapi` was rejected because the current PF
  recovery boundary still requires root and would collapse privilege separation.
- Introducing a persistent configuration-file format now was deferred until its
  schema, migration, ownership, and compatibility policy are designed.
