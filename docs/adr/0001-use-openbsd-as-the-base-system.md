# ADR-0001: Use OpenBSD as the base system

- Status: accepted
- Date: 2026-09-18

## Context

Gatehold needs a maintained operating-system foundation with a strong network
stack, a mature stateful firewall, secure defaults, auditable base utilities,
and a coherent release process. Developing or maintaining a separate kernel,
packet filter, routing stack, or installer would consume effort without creating
the product's distinguishing value.

## Decision

Gatehold will use an upstream OpenBSD release as its base. It will integrate
native components such as PF, `pfctl`, `pflog`, `rcctl`, WireGuard, and `iked`.
The project will initially ship management software and package metadata rather
than maintaining a deep OpenBSD fork.

Upstream configuration remains the final executable representation. Gatehold
will render and validate native configuration; it will not replace PF with a
new packet-filter implementation.

## Consequences

- OpenBSD releases create a recurring integration and regression-test cycle.
- Hardware support is constrained by OpenBSD and must be documented explicitly.
- Development can occur on Linux, but native OpenBSD tests are mandatory.
- Gatehold can focus on safe management, observability, updates, and recovery.
- Any future base-system patch must be exceptional, narrowly scoped, and
  justified by a separate ADR.

## Security impact

Staying near upstream reduces locally maintained privileged code. Gatehold must
still secure its own controller, API, update channel, generated configuration,
and migration logic.

## Alternatives considered

- FreeBSD would align more closely with OPNsense and pfSense but does not match
  Gatehold's chosen OpenBSD-native identity.
- Linux provides broad hardware support but would change the PF-centered design.
- A new or deeply forked operating system would be operationally unrealistic for
  the initial team and increase security-maintenance risk.

