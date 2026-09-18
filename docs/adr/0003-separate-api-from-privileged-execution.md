# ADR-0003: Separate the API from privileged execution

- Status: accepted
- Date: 2026-09-18

## Context

A web interface and network-facing API process complex, attacker-controlled
input. PF activation and managed system files require elevated privileges.
Combining both roles would turn any web vulnerability into unrestricted control
of the firewall host.

## Decision

Gatehold will separate the network-facing API from a small privileged
controller. The API runs as a dedicated unprivileged user. The controller is
reachable only through a local Unix-domain socket and exposes versioned,
narrowly scoped operations.

The controller will not expose a generic shell, arbitrary executable path,
arbitrary argument list, or unrestricted filesystem operation. Authorization is
checked for the requested capability and target, not inferred from the caller's
high-level goal.

## Consequences

- The local protocol becomes a security boundary and requires schema/version
  handling, size limits, authentication, timeouts, and negative tests.
- Some workflows require coordination across processes.
- Compromise of the API should not directly grant general root execution.
- Operations become individually auditable and suitable for policy decisions.

## Security impact

The controller will use least privilege, dedicated ownership, strict input
validation, fixed executable paths, direct process execution without a shell,
and OpenBSD `pledge`/`unveil` where compatible with required operations.

## Alternatives considered

- A single root web service was rejected because its attack surface and impact
  are too large.
- `doas` rules for many helper commands were rejected as the primary interface
  because they do not provide a sufficient typed operation boundary.
- Direct API edits of `/etc` were rejected because they make transactions,
  validation, audit, and rollback unreliable.

