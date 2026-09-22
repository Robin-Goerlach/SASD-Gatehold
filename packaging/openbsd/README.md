# OpenBSD service packaging

Status: **experimental integration-lab artifact; not a production package**

This directory contains the first native OpenBSD service definition for the
read-only `gateholdd` bootstrap. It follows `rc.d(8)`/`rc.subr(8)`, leaves the
daemon in the foreground, backgrounds it through `rc_bg=YES`, disables reload,
and runs the daemon's side-effect-free `check-config` operation through the same
`rc_exec` identity boundary before start or restart.

Production appliances will install versioned and signed packages. They will not
build from a Git checkout and will not require Git, Node.js, compilers, or other
development tooling.

## Package layout

The intended package layout is:

| Installed path | Owner/mode | Purpose |
|---|---|---|
| `/usr/local/sbin/gateholdd` | `root:bin`, `0555` | Privileged controller daemon |
| `/usr/local/bin/gateholdctl` | `root:bin`, `0555` | Unprivileged command-line client |
| `/etc/rc.d/gateholdd` | `root:wheel`, `0555` | OpenBSD service definition |
| `/var/log/gatehold` | `root:wheel`, `0700` | Durable operation journal |
| `/var/db/gatehold/revisions` | `root:wheel`, `0700` | Immutable PF revisions |
| `/var/db/gatehold/transactions` | `root:wheel`, `0700` | Pending activation and process lock |
| `/var/run/gatehold` | `root:_gateholdapi`, `0750` | Local controller endpoint parent |

The API account is intentionally separate from root. The root controller owns
the socket parent and explicitly assigns the bound socket to the API account's
primary group with mode `0660`. Kernel peer authentication still requires the
exact configured UID and GID.

## Isolated-lab provisioning

Run these steps only on a disposable OpenBSD test system. Package account and
directory declarations will replace the manual commands before a supported
release.

Create a disabled, non-login API identity without a home directory:

```console
# useradd -c "SASD Gatehold API" -d /nonexistent -g =uid \
    -s /sbin/nologin _gateholdapi
# api_uid=$(id -u _gateholdapi)
# api_gid=$(id -g _gateholdapi)
```

Provision each trust root independently. Do not make a storage root or the
socket parent group-writable:

```console
# install -d -o root -g wheel -m 0700 /var/log/gatehold
# install -d -o root -g wheel -m 0700 /var/db/gatehold
# install -d -o root -g wheel -m 0700 /var/db/gatehold/revisions
# install -d -o root -g wheel -m 0700 /var/db/gatehold/transactions
# install -d -o root -g _gateholdapi -m 0750 /var/run/gatehold
```

Install the service definition for a source-tree lab build:

```console
# install -o root -g wheel -m 0555 \
    packaging/openbsd/rc.d/gateholdd /etc/rc.d/gateholdd
```

Configure numeric identities through `rcctl`; the privileged executable does
not perform user-database lookup:

```console
# rcctl set gateholdd flags \
    --journal-root /var/log/gatehold \
    --revision-root /var/db/gatehold/revisions \
    --transaction-root /var/db/gatehold/transactions \
    --socket-path /var/run/gatehold/controller.sock \
    --allowed-uid "$api_uid" \
    --allowed-gid "$api_gid"
# rcctl enable gateholdd
# rcctl configtest gateholdd
# rcctl start gateholdd
# rcctl check gateholdd
```

After provisioning a disposable VM, run the guarded
[service lifecycle test](../../docs/lab/openbsd-service-lifecycle-test.md) to
verify native configtest, start, restart, cooperative stop, socket delegation,
and journal evidence. The harness refuses to run with a pending activation or
an already-running daemon and does not change the configured service.

`rcctl configtest gateholdd` checks command-line structure, identity policy,
canonical directories, ownership, permissions, and directory identities. It
does not acquire the process lock, create a journal, touch PF, replace or remove
a socket, or require the live socket path to be absent. Startup repeats those
checks and additionally requires an absent socket path before recovery.

The service redirects standard output and error to `daemon.info`. The durable
operation journal remains authoritative. Neither stream may contain secrets,
numeric peer identities, configured paths, or request payloads.

## Current limitations

- This is not yet an OpenBSD package or signed repository artifact.
- Account creation and trust-root provisioning are still manual lab steps.
- `/var/run/gatehold` must exist with the documented identity after every boot;
  native lab testing must confirm the final package lifecycle.
- The bootstrap activation policy denies every new PF activation.
- Native service start, stop, restart, socket group delegation, and shutdown
  deadlines have a guarded harness but still require recorded OpenBSD lab
  evidence. Boot ordering, crash recovery, syslog routing, and controller
  status requests do not yet have native lifecycle coverage.
- No production support or compatibility guarantee exists for this pre-alpha
  artifact.
