# Privileged PF controller lifecycle

Status: **experimental library API; recovery-gated service loop integrated, no
privileged daemon executable yet**

`PrivilegedPfController` is the mandatory in-process gate between a future
controller request handler and `PfActivationService`. It ensures restart
recovery completes before the first activation can be dispatched.

## States

| State | Activation dispatch | Meaning |
|---|---|---|
| `created` | Rejected | `start()` has not run |
| `starting` | Waits on lifecycle lock | Recovery owns the controller |
| `ready` | Accepted | Recovery and controller audit boundaries succeeded |
| `read_only` | Rejected | Safety recovery succeeded, but durable operational evidence or transaction coordination degraded |
| `blocked` | Rejected | Safe PF state could not be established or rollback failed |

Transitions to `read_only` and `blocked` are terminal for that controller
instance. Constructing a new instance and calling `start()` is the only recovery
path; this forces durable state to be examined again.

## Startup contract

`start()` performs these steps synchronously while holding the lifecycle lock:

1. change `created` to `starting`;
2. append `GH-CTL-0001` startup intent;
3. call `PfActivationService::recover_pending()`;
4. enter `blocked` if recovery fails;
5. enter `read_only` if recovery succeeded without durable audit evidence;
6. append `GH-CTL-0002` and enter `ready` only if that append succeeds.

The recovery call is made even when the initial startup audit append fails.
Restoring a possibly unsafe active ruleset takes precedence, but activation
dispatch remains disabled because the recovery could not be fully audited.

Repeated `start()` calls return the current terminal startup state and do not
run recovery again.

## Dispatch contract

`activate()` holds the same lifecycle lock as startup. Outside `ready`, it
returns `controller_not_ready`, emits best-effort `GH-CTL-1001`, and does not
call the activation service. The rejection event uses the fixed operation ID
`controller-dispatch`; a request identifier is not trusted before dispatch.

After a dispatched operation, the activation result can degrade the controller:

| Activation status | Controller state |
|---|---|
| `rollback_failed` | `blocked` |
| `audit_failed`, `audit_failed_rolled_back` | `read_only` |
| `transaction_conflict`, `transaction_store_failed` | `read_only` |
| `committed_with_warning`, `committed_cleanup_pending` | `read_only` |
| All other completed statuses | Remain `ready` |

An activation may be durably committed and still return a successful
`ControllerActivationResult::ok()` while the controller enters `read_only`.
Callers must inspect both the operation result and returned controller state.

## Event identifiers

| Event ID | Meaning |
|---|---|
| `GH-CTL-0001` | Controller startup and mandatory recovery began |
| `GH-CTL-0002` | Recovery completed; activation dispatch enabled |
| `GH-CTL-1001` | Dispatch rejected because controller is not ready |
| `GH-CTL-1002` | Repeated startup returned current state |
| `GH-CTL-2001` | Recovery failed; controller blocked |
| `GH-CTL-2002` | Audit unavailable; controller read-only |
| `GH-CTL-2003` | Activation rollback failed; controller blocked |
| `GH-CTL-2004` | Activation safety state degraded; controller read-only |

## Concurrency guarantee

Startup, activation dispatch, and state inspection are serialized within one
controller instance. A request queued after startup begins cannot call the
activation service until recovery returns and the ready audit record is durable.
The transaction store remains the cross-process conflict guard.

## Current boundary

The lifecycle object and failure-injection tests are implemented. An
authenticated, bounded session schema dispatches status and activation through
it using kernel peer credentials. A serial library listener owns a private
filesystem socket without replacing existing entries. A stop-token-driven
service loop calls recovery before listener admission and bounds repeated
listener failures. `gateholdd serve-read-only` composes the lifecycle with
synchronous signal handling, filesystem preflight, process exclusivity, and an
OpenBSD process sandbox. Tests use controlled sockets and a `pfctl` substitute
and never touch the host firewall. Supervisor integration, native
sandbox/recovery coverage, and production authorization remain pending. Real PF
activation therefore remains disabled pending a disposable OpenBSD lab path
and production collaborators.
