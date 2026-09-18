# ADR-0007: Store validated revisions immutably

- Status: accepted
- Date: 2026-09-18

## Context

A rendered candidate is temporary and identified by an operation ID. Activation
and rollback need durable configuration revisions whose contents cannot be
silently replaced after native validation. Gatehold must also distinguish a
prepared revision from the revision known to have worked after activation and
health verification.

## Decision

After portable and native validation succeed, the preparation service copies the
private candidate into an owner-controlled revision directory. Revisions use a
fixed-width numeric filename, private mode, exclusive creation, no-follow
semantics, and synchronized file and directory writes. A revision number can be
stored exactly once; an existing revision is never overwritten.

The last-known-good revision is stored as a separate private marker containing
only a decimal revision number. Updating the marker writes and synchronizes a
private temporary file and atomically renames it into place. The referenced
revision must already exist and pass type, ownership, permission, and size
checks.

Preparation stores the revision but does **not** update last known good. Only a
future activation workflow may do so after the new ruleset is active, required
health probes pass, and any confirmation requirement has been satisfied.

## Consequences

- A prepared revision remains available for review and later activation.
- Reusing a revision number fails rather than mutating historical content.
- Rollback code can later load a specific immutable revision.
- Revision numbers must be positive and managed monotonically by a future
  configuration repository.
- Storage consumes space until an explicit retention policy is implemented.
- Filesystem ownership protects integrity against unprivileged processes, but
  the initial store is not cryptographically tamper-evident against root.

## Security impact

The API process must not share the revision-store identity or write access. The
controller-owned directory is part of the trust boundary. Symbolic-link sources,
public candidate files, unsafe roots, oversized content, and duplicate revisions
are rejected.

There remains a path-based native-validation/copy boundary: `pfctl` and the
revision store open the candidate at different moments. The private staging
directory prevents unprivileged replacement; later hardening may validate and
copy through stable descriptors or add content digests.

## Alternatives considered

- Reusing the temporary candidate as the revision was rejected because candidate
  lifecycle and durable history have different requirements.
- Overwriting a revision was rejected because it would make audit and rollback
  ambiguous.
- Automatically marking every prepared revision last known good was rejected
  because syntax validity does not prove successful activation or connectivity.
- A symlink as the authoritative last-known-good marker was rejected in favor of
  a small regular file that can be validated without following links.

