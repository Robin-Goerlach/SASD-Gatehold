# Architecture

This section will describe Gatehold's component boundaries, privileges, data
flows, configuration lifecycle, recovery behavior, and integration with native
OpenBSD services.

The first documents planned for this directory are:

- system context and trust-boundary diagram;
- controller/API process model;
- desired-state configuration model;
- render, validate, apply, verify, confirm, and rollback sequence;
- event and audit pipeline;
- update and recovery architecture.

Until those documents are accepted, the architecture in the root README is the
current high-level direction rather than a stable public interface.

## Current documents

- [Configuration lifecycle](configuration-lifecycle.md) — mandatory stages
  from structured intent through validation, activation, confirmation, and
  rollback.

