# ADR-0021: Delegate the controller socket to an API group

- Status: accepted
- Date: 2026-09-19

## Context

The controller must retain root authority for narrowly bounded PF operations,
while the future API runs as a separate unprivileged account. A mode `0600`
socket cannot connect those identities. Depending on the root process's
effective group or set-group-ID inheritance would either place the API account
in a privileged group or make the resulting socket group implicit.

Filesystem reachability is defense in depth; the protocol still authenticates
the kernel-reported peer UID and GID. Nevertheless, the socket should expose no
broader connection surface than that peer policy requires.

## Decision

`--allowed-gid` selects mode `0660` and becomes the explicit socket target GID.
The filesystem preflight requires the daemon-owned socket parent to have that
GID, group traversal, no group write, and no permissions for other users.

After `bind()`, the listener verifies that the new entry is a socket owned by
the effective daemon UID and records its device and inode. It uses `fchownat()`
relative to the already verified parent descriptor with
`AT_SYMLINK_NOFOLLOW`, applies mode `0660`, and re-verifies type, owner, group,
mode, device, and inode before `listen()`. Any failure closes and removes only
the listener-owned inode. Mode `0600` rejects a target group; mode `0660`
rejects a missing target group.

Only effective UID 0 may select a target GID different from its effective GID.
An unprivileged daemon may use `0660` only with its own effective group. The
OpenBSD parent adds the narrow `chown` pledge promise; its locked `unveil()`
view still limits the operation to the configured socket parent.

## Consequences

- The API account can remain outside the controller's privileged groups.
- Socket group selection is explicit and verified rather than inherited.
- Packaging must create the socket parent with root ownership, the API group,
  mode `0750`, and no pre-existing socket entry.
- The privileged process retains `chown` authority inside its unveiled paths.

## Security impact

The change reduces identity coupling between the API and controller. It does
not replace kernel peer authentication: a process that can reach the socket
must still present the exact configured UID and GID before request parsing or
dispatch. Path-relative, no-follow operations plus final identity verification
limit replacement races but do not defend against root or a compromised daemon.

## Operational impact

An incorrect parent GID, missing group traversal, inconsistent mode/group pair,
or failed ownership change rejects startup. Readiness records whether group
delegation was selected without logging numeric identities or filesystem paths.
OpenBSD packaging must resolve account names to numeric IDs before invoking the
daemon; the privileged process performs no user-database lookup.

Portable tests cover identity policy, configuration coupling, preflight, and
sandbox promises. Native OpenBSD verification of `fchownat()` under the locked
`unveil()`/`pledge()` policy remains mandatory before production use.

## Alternatives considered

- Adding the API user to the controller's effective group was rejected because
  that group may grant unrelated privileged filesystem access.
- Relying on set-group-ID directory inheritance was rejected because the
  listener would not explicitly establish the security-relevant group.
- Making the socket world-accessible and trusting peer credentials alone was
  rejected because it needlessly broadens the reachable attack surface.
- Dropping the controller permanently to the API group was rejected because PF
  recovery and activation still require a separately designed privilege model.
