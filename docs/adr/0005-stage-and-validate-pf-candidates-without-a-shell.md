# ADR-0005: Stage and validate PF candidates without a shell

- Status: accepted
- Date: 2026-09-18

## Context

Rendered PF configuration must be checked by OpenBSD's native parser before it
can ever be considered for activation. Passing generated paths or content
through a shell would create an unnecessary command-injection boundary. Writing
candidates through ordinary path-based streams could permit traversal,
symlink-following, accidental overwrite, or overly broad permissions.

## Decision

Gatehold stages each candidate under a configured absolute directory that is:

- a real directory rather than a symbolic link;
- owned by the effective user of the controller;
- not writable by group or others.

Operation IDs are constrained to a short ASCII identifier alphabet. Files are
created relative to an opened directory descriptor with `openat`, `O_EXCL`,
`O_NOFOLLOW`, `O_CLOEXEC`, and mode `0600`. The contents and directory entry are
synchronized before staging succeeds. A candidate is write-once for its
operation ID.

Native validation starts an absolute executable path directly with an argument
vector equivalent to:

```text
/sbin/pfctl -nf /absolute/staging/path/operation-id.pf.conf
```

No command shell, command string, globbing, variable expansion, or search via
`PATH` is involved. Validation has a bounded runtime and bounded captured
output. Exit code zero means syntactically accepted; no ruleset is loaded.

## Consequences

- Candidate paths cannot contain arbitrary user text.
- Existing candidates are never silently replaced.
- Production setup must create and permission the staging root before use.
- A stalled native validator is terminated instead of blocking the controller.
- Truncated diagnostics are explicitly marked.
- Native OpenBSD integration remains necessary because the Linux CI test uses a
  controlled substitute for `pfctl`.

## Security impact

The design removes shell interpretation and narrows filesystem races. The
staging directory must be accessible only to the privileged controller; using
the same Unix account for the API and controller would weaken the guarantee.

The current check of a candidate path and the later open by `pfctl` are separate
operations. The protected, controller-owned staging directory is therefore a
required part of the security boundary, not just an installation detail.

## Alternatives considered

- `system()` or `/bin/sh -c` was rejected because quoting is not a reliable
  security boundary.
- Reusing a fixed candidate filename was rejected because it complicates
  concurrency, audit correlation, and write-once behavior.
- Supplying PF text on standard input was deferred because native behavior and
  error reporting must first be verified on supported OpenBSD releases.
- Loading with `pfctl -f` during validation was rejected because validation must
  remain side-effect free.

