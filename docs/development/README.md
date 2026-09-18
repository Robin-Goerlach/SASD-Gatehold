# Development guide

Gatehold uses modern C++, CMake, and CTest. Fast portable checks run on Linux;
native behavior is verified on OpenBSD before release.

## Local build

```console
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Useful development-only demonstrations:

```console
./build/src/gateholdctl render-example
./build/src/gateholdctl event-example
```

`render-example` only writes candidate PF text to standard output. It does not
invoke `pfctl` or modify the host.

The native-validation test uses a purpose-built helper executable rather than
the host firewall. It verifies direct argument passing, safe staging, rejection,
timeouts, and bounded output without requiring root or modifying PF.

The preparation and journal tests additionally verify concurrent JSONL appends,
secret redaction, hard capacity limits, fail-closed audit behavior, the complete
nine-event success sequence, immutable revision storage, and terminal error
mappings. They still perform no PF activation.

The real OpenBSD PF test is opt-in and documented in the
[lab guide](../lab/openbsd-pfctl-smoke-test.md). A green Linux CI run does not
claim native OpenBSD validation.

## Definition of done for a change

- behavior and scope are documented;
- automated tests cover the normal and relevant failure paths;
- compiler warnings are clean;
- errors are actionable and contain stable identifiers where applicable;
- logs contain no secrets;
- privilege and rollback implications are reviewed;
- OpenBSD-specific behavior is tested natively when relevant;
- user and reference documentation are updated.

Formatting, static-analysis, sanitizer, fuzzing, and package-building commands
will be added as the corresponding tools are adopted through ADRs.
