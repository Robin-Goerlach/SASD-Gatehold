# Documentation

This directory is the documentation home for SASD Gatehold. Documentation is
kept beside the implementation so architectural and operational changes can be
reviewed together with code.

## Sections

| Directory | Purpose |
|---|---|
| [`architecture/`](architecture/) | Components, trust boundaries, data flow, and configuration lifecycle |
| [`adr/`](adr/) | Numbered Architecture Decision Records and their status |
| [`security/`](security/) | Threat model, privilege model, logging redaction, and disclosure guidance |
| [`development/`](development/) | Build standards, coding conventions, test strategy, and release workflow |
| [`lab/`](lab/) | Reproducible KVM topology, deployment, reset, and integration tests |
| [`user-guide/`](user-guide/) | Installation, configuration, operation, backup, and recovery |
| [`reference/`](reference/) | CLI, API, schemas, event IDs, file formats, and support bundles |

## Documentation principles

- Clearly label proposed, experimental, and implemented behavior.
- Record significant technical decisions as ADRs.
- Include failure behavior and rollback, not only the successful path.
- Never place real credentials, private addresses, private keys, or unredacted
  production logs in documentation examples.
- Keep commands copyable and state the platform on which they are intended to
  run.
- Maintain English and German documentation where practical; prefer correctness
  over incomplete duplicated text.

