# ADR-0006: Fail closed on audit-journal failure

- Status: accepted
- Date: 2026-09-18

## Context

Gatehold must be able to reconstruct who requested a firewall operation, which
revision was processed, how far it progressed, and why it stopped. Logging only
after a privileged action can leave an unrecorded security-relevant change when
the journal is unavailable, full, unsafe, or corrupted.

The first preparation pipeline does not activate PF, but its ordering establishes
the rule later privileged workflows must follow.

## Decision

Gatehold uses an append-only JSONL operation journal. Before a preparation stage
with a filesystem or process side effect begins, the service synchronously
records the intent. It records the result before advancing to the next stage.
If a required append fails, the operation returns `audit_failed` and does not
start another stage.

The journal:

- resides below an absolute, owner-controlled, non-symlink directory;
- is an owner-only regular file created with no-follow semantics and mode `0600`;
- uses append mode and an exclusive advisory lock for complete concurrent lines;
- serializes structured `gatehold.event.v1` events with secret-key redaction;
- calls `fsync` before an append is reported successful;
- rejects entries larger than 64 KiB;
- stops growing at 16 MiB until a future trusted rotation mechanism handles it.

Native validator output is kept outside the audit event by default because it
may contain network details. The audit event records the result, exit code, and
whether diagnostic output was truncated.

## Consequences

- Audit availability becomes part of operation availability.
- A full journal stops new preparation operations rather than silently dropping
  evidence.
- Administrators will need explicit monitoring and a safe rotation workflow.
- The JSONL file is easy to inspect and feed into later Gatehold Insight tooling.
- A locally privileged attacker can still alter the file; the initial journal is
  durable and private, but not yet cryptographically tamper-evident.

## Security impact

The design prevents normal Gatehold operation from bypassing a missing audit
trail. Locking prevents cooperating Gatehold processes from interleaving JSON
records. Size limits reduce disk-exhaustion risk, while fail-closed behavior
makes capacity exhaustion visible.

## Alternatives considered

- Best-effort asynchronous logging was rejected because loss may be silent.
- Logging only a final result was rejected because crashes would hide the last
  attempted transition.
- Syslog alone was deferred as the authoritative journal because delivery and
  persistence guarantees depend on external configuration.
- An embedded database may become appropriate later, but JSONL keeps the first
  format inspectable while the operation model is evolving.

