# Contributing to SASD Gatehold

Thank you for helping build Gatehold. The project is pre-alpha and currently
focuses on architecture, safety mechanisms, diagnostics, and a narrow vertical
prototype.

## Before changing code

1. Check existing issues and architecture decisions.
2. Keep the change small enough to review and test independently.
3. Describe the failure and rollback behavior for security-relevant work.
4. Do not add a runtime dependency without documenting its maintenance and
   supply-chain impact.

## Build and test

```console
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
  -DGATEHOLD_WARNINGS_AS_ERRORS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Native OpenBSD behavior must also be tested on a supported OpenBSD environment
when a change touches process isolation, PF, interfaces, routing, system files,
service management, packaging, or updates.

## Pull requests

Explain the intent, boundaries, tests, user-visible effect, logging behavior,
and documentation changes. For privileged or configuration-changing code,
include validation, verification, and rollback considerations.

Never include secrets, real private keys, access tokens, unredacted production
logs, or packet payloads in commits, issues, or test fixtures.

