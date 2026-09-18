# ADR-0004: Use a transactional configuration lifecycle

- Status: accepted
- Date: 2026-09-18

## Context

Firewall and routing changes can disconnect their administrator, leave multiple
services inconsistent, or fail only after apparently successful syntax checks.
Simple file replacement followed by service reload is not a sufficient safety
model for local users, automation, or agent-assisted administration.

## Decision

Every managed change will follow a versioned lifecycle: draft, model validation,
render, native validation, activation, verification, confirmation, and commit.
Failure or confirmation timeout restores the last known-good revision.

The change record will identify the requester, authorization decision,
configuration revision, operation ID, affected components, validation results,
activation result, probes, confirmation deadline, and final state.

## Consequences

- Even small features require explicit validation, health checks, and rollback
  behavior before becoming writable through the UI or API.
- The implementation needs durable revision and operation journals.
- High-risk changes take longer but are diagnosable and recoverable.
- Read-only and render-only capabilities can be released before activation.

## Security impact

The lifecycle reduces lockout and partial-configuration risks, but only if the
rollback mechanism is independent of the requesting web session and survives
controller failure. The last known-good revision must be protected against
unauthorized modification.

## Alternatives considered

- Immediate in-place editing was rejected because it has no atomicity or
  dependable recovery path.
- Syntax validation without post-activation probes was rejected because a valid
  ruleset may still break required connectivity.
- Manual backup and recovery alone were rejected because remote lockout often
  prevents timely repair.

