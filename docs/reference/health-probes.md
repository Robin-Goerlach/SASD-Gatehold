# Post-activation health probes

Status: **experimental library API; portable tests use controlled endpoints**

Health probes run after the candidate PF ruleset is loaded and before explicit
confirmation. Any unhealthy, timed-out, or execution-error result causes the
activation service to restore the last-known-good revision.

## Shared contract

Every `HealthProbe` supplies a safe unique identifier and implements:

```cpp
HealthProbeResult run(std::chrono::milliseconds timeout) const;
```

The activation service permits probe deadlines from 100 milliseconds through
60 seconds. Concrete probes also enforce a positive maximum of 60 seconds when
called directly. Exceptions are converted into `execution_error` and rollback.

| Status | Meaning |
|---|---|
| `healthy` | The bounded observation succeeded |
| `unhealthy` | The observation completed and found the path unavailable |
| `timed_out` | The observation did not finish before its deadline |
| `execution_error` | Configuration or the local probing mechanism failed |

## PF control-plane probe

`PfctlInfoProbe` runs the absolute trusted executable path with exactly:

```text
/sbin/pfctl -s info
```

It uses no shell, captures at most 64 KiB across standard output and error, and
kills the child at the deadline. Exit zero is healthy. A non-zero result is
unhealthy; launch failure, unsafe timeout, or excessive output is an execution
error.

This proves that `pfctl` can query PF after activation. It does not prove every
rule, forwarding path, or application is correct. The command follows the
[`pfctl(8)` status interface](https://man.openbsd.org/pfctl.8).

## TCP management-path probe

`TcpConnectProbe` is constructed with a controller-owned identifier, numeric
address, and port. Hostnames are deliberately not resolved. The probe:

1. parses the address with `inet_pton()`;
2. creates a non-blocking close-on-exec TCP socket;
3. starts one connection attempt;
4. waits with `poll()` against a monotonic deadline;
5. reads `SO_ERROR` to distinguish success from failure;
6. closes the descriptor on every path.

This follows the completion sequence documented by
[`connect(2)`](https://man.openbsd.org/connect.2). Connection refusal or routing
failure is unhealthy; expiry is timed out; local socket/poll failures are
execution errors.

Rejected endpoints include:

- DNS names;
- port zero;
- IPv4/IPv6 wildcard addresses;
- multicast and limited broadcast addresses;
- IPv4-mapped IPv6 addresses, which add representation ambiguity;
- IPv6 link-local addresses, because a trusted scope/interface model is not yet
  represented.

A successful TCP connection proves only that the selected endpoint completed a
handshake from the controller's network context. It does not authenticate the
peer or validate an application response.

## Audit and diagnostics

The durable operation journal contains `GH-ACT-0004` intent followed by a
generic `GH-PROBE-*` outcome. It includes the probe ID, operation ID, and
revision. It does not include the configured address, port, `pfctl` output, or
native socket error text. Detailed result messages returned in memory are also
generic and contain no endpoint.

| Event ID | Meaning |
|---|---|
| `GH-PROBE-0001` | Probe completed healthy |
| `GH-PROBE-1001` | Probe completed unhealthy |
| `GH-PROBE-2001` | Probe deadline expired |
| `GH-PROBE-2002` | Probe configuration or execution failed |

## Current boundary

The probes are implemented and failure-injection tested on Linux with a
controlled `pfctl` substitute and loopback listeners. They have not yet run as
part of a real activation in the disposable OpenBSD lab. The production daemon
must construct them from trusted configuration; activation requests must never
select or alter probe targets.
