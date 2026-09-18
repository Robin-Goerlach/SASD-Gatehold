# ADR-0011: Use bounded controller-selected health probes

- Status: accepted
- Date: 2026-09-18

## Context

Activation rollback currently depends on an abstract health-probe contract.
Test doubles prove orchestration, but a production controller needs concrete
observations after loading a candidate ruleset. A generic command probe would
expand the privileged interface into arbitrary process execution. A hostname-
based network probe would add DNS behavior and could turn request data into an
SSRF primitive.

## Decision

Gatehold provides two small post-activation probes selected and constructed by
the trusted controller:

1. `PfctlInfoProbe` directly executes the configured absolute `pfctl` path with
   the fixed argument vector `-s info`. It uses the existing bounded process
   runner and accepts only a positive timeout of at most 60 seconds.
2. `TcpConnectProbe` attempts one non-blocking TCP connection to a preconfigured
   numeric IPv4 or IPv6 address and port. It performs no DNS lookup, uses
   `poll()` against an absolute monotonic deadline, and confirms completion with
   `getsockopt(SO_ERROR)`.

The TCP probe rejects zero ports, wildcard addresses, multicast addresses,
limited broadcast, and IPv6 link-local addresses without an explicit scope
model. Probe identifiers are still validated by the activation service before
PF mutation.

Neither probe logs native output, target addresses, ports, or detailed socket
errors. The activation journal records only the allowlisted probe ID, generic
outcome, revision, and operation correlation.

## Consequences

- The activation service can use real bounded observations without accepting a
  caller-selected executable or argument vector.
- Management-path reachability is independent of DNS availability and search
  configuration.
- A refused connection is distinguishable from a deadline expiration or local
  execution failure.
- Multiple controller-selected probes remain mandatory for broader safety
  claims; a successful TCP handshake alone does not prove application health.
- Scoped IPv6 link-local management endpoints require a future explicit
  interface/scope representation.

## Security impact

The fixed PF argv avoids shell and argument injection. Numeric-only endpoints
avoid DNS rebinding; controller-owned construction prevents a request from
selecting an arbitrary host. The non-blocking socket, monotonic deadline,
close-on-exec flag, and bounded PF output prevent a probe from waiting or
capturing data indefinitely.

The controller must construct probes from trusted appliance configuration. The
future local protocol must not allow an activation request to replace their
identifier, executable, address, or port.

## Operational impact

At least one PF control-plane probe and the relevant management endpoints should
be configured before enabling activation. Operators must choose endpoints whose
availability genuinely indicates that the new policy preserved administrative
access. Application-level request/response probes can be added later where a
TCP handshake is insufficient.

## Alternatives considered

- A generic executable probe was rejected because it creates an arbitrary
  command surface in the privileged process.
- Hostname resolution was rejected because it adds DNS dependency, ambiguity,
  and rebinding risk during a firewall transaction.
- A blocking socket with receive/send timeouts was rejected because connection
  establishment would not be bounded reliably across platforms.
- Parsing human-readable `pfctl -s info` output was deferred because exit status
  and control-plane access are stable signals, while localized or revised text
  formats would be brittle. Policy and data-path behavior require separate
  probes.
