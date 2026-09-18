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
