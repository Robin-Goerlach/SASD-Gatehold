# Architecture Decision Records

Significant decisions are recorded here so future contributors can understand
both the choice and its context.

Use sequential filenames such as:

```text
0001-use-openbsd-as-the-base-system.md
0002-use-modern-cpp-for-core-services.md
0003-separate-api-and-privileged-controller.md
```

Each ADR should contain: title, status, context, decision, consequences,
security impact, operational impact, and alternatives considered. Valid status
values are `proposed`, `accepted`, `superseded`, and `rejected`.

## Accepted decisions

- [ADR-0001: Use OpenBSD as the base system](0001-use-openbsd-as-the-base-system.md)
- [ADR-0002: Use modern C++ for core services](0002-use-modern-cpp-for-core-services.md)
- [ADR-0003: Separate the API from privileged execution](0003-separate-api-from-privileged-execution.md)
- [ADR-0004: Use a transactional configuration lifecycle](0004-use-a-transactional-configuration-lifecycle.md)
- [ADR-0005: Stage and validate PF candidates without a shell](0005-stage-and-validate-pf-candidates-without-a-shell.md)
- [ADR-0006: Fail closed on audit-journal failure](0006-fail-closed-on-audit-journal-failure.md)
- [ADR-0007: Store validated revisions immutably](0007-store-validated-revisions-immutably.md)
- [ADR-0008: Require authorized, verified, and confirmed PF activation](0008-require-authorized-confirmed-pf-activation.md)
- [ADR-0009: Persist pending activation before PF mutation](0009-persist-pending-activation-before-mutation.md)
- [ADR-0010: Gate activation on controller recovery](0010-gate-activation-on-controller-recovery.md)
- [ADR-0011: Use bounded controller-selected health probes](0011-use-bounded-controller-selected-health-probes.md)
- [ADR-0012: Authenticate and bound local controller sessions](0012-authenticate-and-bound-local-controller-sessions.md)
- [ADR-0013: Bind local controller sockets without replacement](0013-bind-local-controller-sockets-without-replacement.md)
- [ADR-0014: Run controller recovery before service admission](0014-run-controller-recovery-before-service-admission.md)
- [ADR-0015: Convert POSIX signals with synchronous waiting](0015-convert-posix-signals-with-synchronous-waiting.md)
- [ADR-0016: Bootstrap with a deny-all foreground daemon](0016-bootstrap-with-a-deny-all-foreground-daemon.md)
- [ADR-0017: Preflight daemon filesystems before recovery](0017-preflight-daemon-filesystem-before-recovery.md)
- [ADR-0018: Exclude concurrent daemon recovery](0018-exclude-concurrent-daemon-recovery.md)
- [ADR-0019: Constrain the daemon with an OpenBSD process sandbox](0019-constrain-daemon-with-openbsd-process-sandbox.md)
- [ADR-0020: Rate-limit local controller admission](0020-rate-limit-local-controller-admission.md)
- [ADR-0021: Delegate the controller socket to an API group](0021-delegate-controller-socket-to-api-group.md)
- [ADR-0022: Supervise the bootstrap daemon with OpenBSD rc.d](0022-supervise-bootstrap-daemon-with-openbsd-rcd.md)
- [ADR-0023: Verify the OpenBSD service lifecycle with a guarded harness](0023-verify-openbsd-service-lifecycle-with-a-guarded-harness.md)
