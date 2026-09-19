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

The loader and activation-service tests use the same controlled helper for both
`-nf` and `-f`. They cover authorization denial, immediate revalidation,
successful commit, failed probes, confirmation timeout, native-load failure,
pre- and post-mutation audit failure, automatic rollback, and critical rollback
failure. The helper records simulated loads; it never opens the host PF device.

The pending-transaction tests additionally cover atomic exclusive creation,
strict phase ordering, malformed and symlink records, concurrent creators,
restart rollback, committed cleanup, idempotent recovery, and recovery while the
audit journal is unavailable.

The controller-lifecycle tests cover rejection before startup, recovery-before-
dispatch ordering under concurrency, idempotent startup, audit-driven read-only
mode, corrupt-state startup blocking, and permanent blocking after rollback
failure.

The concrete health-probe tests cover fixed-argv PF information success,
non-zero exit, timeout and bounded-output failure; numeric TCP success and
refusal; rejection of DNS, wildcard, multicast and invalid-port targets; generic
non-disclosing diagnostics; and concurrent reuse against loopback listeners.

The local-protocol tests use connected Unix `socketpair()` descriptors. They
cover kernel UID/GID extraction, exact peer denial, fragmented and oversized
frames, strict version/identifier parsing, silent-peer timeout, audit failure,
lifecycle-gate enforcement, secret-free logging, successful activation, and the
ambiguous but durable result when a client drops the response connection.

The local-listener tests cover relative, aliased, unsafe, occupied, and
world-accessible paths; audit-before-bind failure; exact socket modes; serial
admission; bounded accept timeouts; status dispatch; competing listeners; clean
shutdown; and preservation of a substituted filesystem entry. Restricted test
runtimes that deny `socket(AF_UNIX, ...)` explicitly skip only the live
bind/listen/accept portion; normal Linux CI and the OpenBSD lab must execute it.

The controller-service tests use a scripted connection acceptor around the real
lifecycle controller. They cover mandatory recovery with a pre-requested stop,
audit failure after recovery, normal and rejected sessions, idle polls,
deadline forwarding, error-streak reset and exhaustion, listener startup and
cleanup failure, saturated lifecycle telemetry, and rejection of concurrent run
loops. They require no socket capability and run in restricted environments.

The daemon tests cover normalized and separated trust-root arguments, numeric
peer identities, duplicate and unknown option rejection, non-disclosing errors,
the concrete deny-all activation providers, and filesystem preflight. They
exercise missing, aliased, misowned, writable, group-inconsistent, and occupied
roots. The process test always verifies durable preflight rejection before
startup and recovery. When filesystem Unix sockets are available, it also
starts the foreground daemon, queries status, verifies activation denial, sends
real `SIGTERM`, and checks clean socket removal and secret-free journal events.
Restricted runtimes skip only this live-socket portion.

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
