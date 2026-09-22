# OpenBSD service lifecycle test

Status: **implemented harness; native execution evidence pending**

`tests/openbsd/service_lifecycle_test.ksh` verifies the installed experimental
`gateholdd` service on a disposable OpenBSD system. It exercises the native
`rc.d` boundary without loading PF rules, changing service configuration, or
deleting an unexpected filesystem entry.

## Safety contract

The harness exits before startup unless all of these conditions hold:

- the exact argument `--confirm-disposable-lab` was supplied;
- the host reports OpenBSD and the caller is root;
- the daemon, client, and service definition have their documented owners and
  read-only executable modes;
- the `_gateholdapi` account resolves to numeric identifiers;
- the enabled service has the exact documented flags, root execution identity,
  and `daemon.info` logger;
- `gateholdd` is stopped and its socket path is absent;
- no `pending-activation` record exists.

The final condition is critical. Daemon startup performs recovery before it
opens the listener. A pending activation can authorize recovery to load a
rollback revision through `pfctl`; this lifecycle test is intentionally not a
PF mutation test and therefore refuses that state.

The exit trap stops only a service instance whose startup was attempted by the
harness. It does not remove sockets, locks, journals, or transactions. A failed
cleanup remains visible for operator investigation.

## Provision and run

Use a disposable console-accessible VM. Install a build at the paths and create
the account and directories described in
[`packaging/openbsd/README.md`](../../packaging/openbsd/README.md). Then run:

```console
# tests/openbsd/service_lifecycle_test.ksh --confirm-disposable-lab
```

Do not run another `rcctl` or direct `gateholdd` operation concurrently. The
harness rejects an already-running process but cannot exclude a separate root
operator racing service state changes between its assertions.

Expected progress is emitted with `GH-LAB-0001`. A refusal or failed assertion
uses `GH-LAB-1001`; an attempted emergency stop uses `GH-LAB-1002`.

The harness proves:

1. `rcctl configtest` succeeds without creating a socket or changing the
   durable journal;
2. `rcctl start` reaches the running state and creates a `root:_gateholdapi`
   mode `0660` socket;
3. `rcctl restart` completes and re-establishes the same endpoint contract;
4. `rcctl stop` completes within the configured timeout and removes the socket;
5. the journal gained exactly two start, ready, SIGTERM, and clean-stop events.

The test leaves the service enabled but stopped. It does not reboot the VM, test
boot ordering, inject a crash, inspect syslog routing, issue a controller status
request, or exercise PF activation and rollback.

## Evidence to retain

Record the OpenBSD release and architecture, Gatehold commit, package or build
identity, console output, and the relevant redacted journal lines. Do not attach
the complete host configuration or unrelated logs to a public report.
