# PF preparation operation

Status: **experimental**

The preparation service combines the non-activating part of Gatehold's
configuration lifecycle. Its successful output is a private PF candidate that
has passed portable model validation and native syntax validation. It does not
load or activate that candidate.

## Successful sequence

| Order | Event | Action | Meaning |
|---:|---|---|---|
| 1 | `GH-OP-0001` | `pf.prepare` | Operation received and journaled |
| 2 | `GH-OP-0002` | `pf.ruleset.render` | Portable validation and rendering succeeded |
| 3 | `GH-OP-0003` | `pf.candidate.stage` | Staging is about to begin |
| 4 | `GH-STAGE-0001` | `pf.candidate.stage` | Private candidate was persisted |
| 5 | `GH-OP-0004` | `pf.ruleset.validate` | Native validation is about to begin |
| 6 | `GH-PF-0001` | `pf.ruleset.validate` | Native validator accepted the candidate |
| 7 | `GH-OP-0005` | `pf.prepare` | Candidate reached prepared state |

All events carry the operation ID and configuration revision. Events specific
to a stage may add bounded metadata such as rule count, candidate byte count,
candidate filename, exit code, or output-truncation state.

## Terminal states

| Status | Meaning |
|---|---|
| `prepared` | All non-activating preparation stages succeeded |
| `invalid_model` | Portable validation rejected the ruleset |
| `staging_failed` | Candidate could not be persisted safely |
| `native_rejected` | Native PF syntax validation returned nonzero |
| `native_timed_out` | Native validator exceeded its deadline |
| `native_execution_error` | Validator could not be executed or supervised |
| `unsafe_candidate` | Candidate failed ownership, type, or permission checks |
| `audit_failed` | Required audit record could not be durably appended |

`audit_failed` takes precedence when recording a stage result fails. A staged
candidate may remain as diagnostic evidence, but no later stage begins.

## Journal storage

The initial journal is `operations.jsonl` under a configured private directory.
Each line is a complete `gatehold.event.v1` JSON object. Concurrent Gatehold
writers coordinate with an exclusive advisory file lock. A successful append
has been synchronized with `fsync`.

Entries are limited to 64 KiB and the complete journal to 16 MiB. Rotation is
not implemented yet. Once full, preparation fails closed with `GH-AUDIT-1005`.
The file is not yet cryptographically tamper-evident.

