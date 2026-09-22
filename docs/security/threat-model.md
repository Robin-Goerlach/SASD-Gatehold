# Initial threat model

Status: **working draft**  
Scope: first transactional PF prototype and its planned administration path

## Security objectives

Gatehold must preserve:

- confidentiality of credentials, VPN keys, configuration secrets, and selected
  network metadata;
- integrity of active and last known-good configuration;
- availability of management and required forwarding paths;
- authenticity and authorization of administrative operations;
- auditability of changes without leaking protected data;
- recoverability after invalid configuration, process failure, or interrupted
  update.

## Assets

| Asset | Primary concern |
|---|---|
| Active PF ruleset | Integrity and availability |
| Last known-good revision | Integrity and recoverability |
| Administrator credentials and sessions | Confidentiality and authenticity |
| VPN and update-signing keys | Confidentiality and integrity |
| Audit journal | Integrity and availability |
| Network and security events | Confidentiality and integrity |
| Gatehold packages and migrations | Authenticity and integrity |
| Privileged controller | Integrity and least privilege |

## Trust boundaries

1. Browser or remote client to the unprivileged API.
2. Unprivileged API to the local privileged controller.
3. Controller to native OpenBSD tools and managed files.
4. Firewall to package and update infrastructure.
5. Gatehold event export to a separate Insight host or external AI provider.
6. Operator-provided support bundle to the maintainer.

Crossing a boundary requires explicit authentication, authorization, schema and
size validation, safe timeouts, and an auditable result.

## Threat actors

- unauthenticated network attacker;
- authenticated user exceeding assigned authority;
- compromised browser or API process;
- malicious or corrupted package, dependency, or update server;
- erroneous administrator action;
- automation or AI agent acting outside its granted capability;
- person receiving an insufficiently sanitized support bundle;
- local attacker with limited access to the appliance.

## Initial threats and controls

| Threat | Initial control direction |
|---|---|
| PF injection through a textual field | Typed values, strict character constraints, no raw PF fragments, negative tests |
| Shell injection | Never compose a shell command; fixed path plus argument vector |
| Candidate path traversal | Restricted operation IDs and directory-relative `openat` creation |
| Symlink or overwrite attack | Trusted non-symlink root, `O_NOFOLLOW`, `O_EXCL`, mode `0600` |
| Hung or excessively noisy validator | Hard timeout, forced termination, bounded output capture |
| Audit-line interleaving | Exclusive file lock and one JSON object per synchronized append |
| Silent loss of audit evidence | Synchronous durable append and fail-closed stage ordering |
| Audit-driven disk exhaustion | Per-entry limit and 16 MiB hard journal limit |
| Sensitive validator diagnostics in audit | Record result metadata, keep native output outside journal by default |
| Validated revision silently replaced | Fixed numeric name, `O_EXCL`, private mode, immutable write policy |
| Last-known-good marker redirected by symlink | Regular-file marker, no-follow reads, atomic rename replaces link itself |
| Prepared but unverified revision treated as safe | Preparation never advances last-known-good marker |
| Administrator lockout | Confirmed commit, independent timer, management-path probe, automatic rollback |
| Probe target or command injection | Controller-selected fixed PF argv and numeric preconfigured TCP endpoints only |
| DNS rebinding during verification | No DNS resolution in management TCP probes |
| Partial multi-service change | Staging, ordered activation, operation journal, compensating rollback |
| API compromise leading to root | Process separation and narrow local controller protocol |
| Local protocol impersonation | Kernel peer credentials plus exact configured UID and optional GID |
| Local protocol resource abuse | 4 KiB frame limit, strict schema, one request per connection, I/O deadlines |
| Request bypasses startup recovery | Protocol activation dispatches only through lifecycle controller |
| Unsafe termination signal handler | Blocked termination signals, synchronous `sigwait()`, cooperative stop token |
| Credential leakage in logs | Attribute-key redaction, field allowlists, tests, no packet payload logging |
| Log forging | Reject control characters in rendered comments; JSON escaping; trusted timestamps at collection |
| Disk exhaustion from diagnostics | Rotation, quotas, bounded fields, temporary trace mode |
| Replay of an administrative request | Authenticated sessions, operation nonce, expiration, idempotency rules |
| Malicious update | Signed repository metadata and packages, version policy, rollback/recovery path |
| AI changes the firewall autonomously | Read-only analysis by default; proposals are separate from approval and activation |
| Support bundle exposes topology | Manifest preview, secret denylist, pseudonymization option, explicit export action |

## Prototype-specific guarantees

The current portable prototype:

- accepts only enumerated rule actions, directions, families, and protocols;
- accepts numeric IP addresses/networks or the literal `any`, not hostnames or PF
  expressions;
- constrains interface names and rule identifiers;
- rejects control characters in descriptions;
- rejects invalid prefixes, mixed families, invalid port/protocol combinations,
  and duplicate rule IDs;
- returns no rendered PF text if any validation issue exists;
- writes a candidate only beneath an absolute, owner-controlled, non-symlink
  staging directory;
- creates candidates as write-once files inaccessible to group and others;
- invokes the native validator directly without a command shell;
- bounds validator runtime and diagnostic output;
- durably journals stage intent and outcome before proceeding;
- stops the pipeline when the audit root, journal, append, or capacity check
  fails;
- stores a successfully validated candidate under an immutable revision number;
- validates and atomically updates the separate last-known-good marker;
- requires an injected trusted authorization decision before activation;
- revalidates the immutable revision immediately before a shell-free PF load;
- requires at least one health probe and explicit confirmation before commit;
- attempts last-known-good rollback after probe, confirmation, commit, load, or
  pre-commit post-mutation audit failure;
- durably records the target, rollback revision, and activation phase before PF
  mutation;
- rejects another activation while a pending transaction exists and provides
  deterministic startup recovery;
- refuses activation dispatch until controller startup recovery completes;
- degrades the controller to read-only on audit or transaction uncertainty and
  blocks it after recovery or rollback failure;
- queries PF through fixed `pfctl -s info` arguments with bounded runtime and
  output;
- checks preconfigured numeric TCP management endpoints with non-blocking
  sockets and a monotonic deadline;
- authenticates Unix peers from kernel credentials before parsing a bounded,
  versioned local request;
- requires durable authentication and dispatch-intent audit before protocol
  operations proceed;
- binds the controller socket only below a canonical controller-owned directory,
  never replaces an existing entry, and removes only its recorded socket inode;
- rate-limits local connections in a bounded monotonic sliding window before
  peer inspection, parsing, request audit, or controller dispatch, with one
  durable activation event and an aggregate shutdown count;
- performs pending-state recovery before service admission and terminates after
  a bounded streak of listener infrastructure failures;
- synchronously consumes blocked `SIGINT` and `SIGTERM` on a dedicated waiter,
  requests cooperative stop, and restores the starting thread's prior mask;
- composes recovery, peer authentication, listener admission, and signal stop
  in a foreground daemon whose bootstrap policy denies every new activation;
- preflights every configured daemon filesystem root and requires the socket
  target to be absent before signal startup or pending-state recovery;
- lets only a root controller delegate its newly bound socket to the exact
  configured API group, then re-verifies owner, group, mode, device, and inode;
- holds a private, identity-checked, nonblocking process lock across recovery,
  service admission, and shutdown audit;
- locks an OpenBSD `unveil()` view to the four configured trust roots,
  `/sbin/pfctl`, and `/dev/pf`, then restricts the long-running parent with a
  minimal reviewed `pledge()` set before recovery or thread creation;
- redacts diagnostic attribute values when their keys indicate common secret
  categories.

The adapters can request native PF validation and loading, but neither path has
yet been exercised as an activation transaction in the Gatehold OpenBSD lab.
The prototype does **not** yet guarantee production authorization, a hardened
privileged process or protocol, persistence of the administrator's desired-state
model, tamper-evident auditing, or update integrity.

## Residual risks and open work

- Native validation needs integration tests on every supported OpenBSD release.
- The staging directory and controller must use a separate privileged account;
  sharing it with the API would weaken the filesystem boundary.
- The initial renderer supports only a small rule subset and needs property and
  fuzz testing before consuming persisted input.
- Attribute-key redaction is defense in depth, not proof that a free-text message
  contains no secret; callers need structured allowlisted fields.
- The protocol, peer policy, listener, service loop, signal bridge, and read-only
  daemon entry point exist, but API service-account provisioning, production
  authorization, credential reduction, and native sandbox verification remain
  to be built. The bootstrap daemon is not a production privileged service.
- Socket-group delegation is covered by portable policy tests, but the actual
  OpenBSD `fchownat()` plus `pledge("chown")` path still requires native lab
  verification before production deployment.
- TCP connection success does not prove peer identity or application health;
  protocol-specific and forwarding-path probes remain open work.
- The lifecycle serializes one controller instance and the on-disk pending
  record rejects a second process. The bootstrap daemon routes every protocol
  activation through that lifecycle and a deny-all authorizer; future protocol
  additions must preserve the same boundary.
- The process lock excludes cooperating daemon starts, but root or a compromised
  daemon identity can replace its named entry. Private directory permissions,
  descriptor identity checks, and component-local validation contain ordinary
  races but cannot defend against that principal.
- The `pfctl` child inherits the locked unveiled filesystem view but currently
  starts without an enforced exec-promise set. Constraining that helper requires
  native OpenBSD validation of syntax checking, loading, and rollback first.
- Non-OpenBSD builds report the sandbox as unsupported and continue only to
  preserve portable process testing. They are not deployable privileged
  services.
- Injected probes and the confirmation gate are trusted to honor their timeout
  contracts. Production implementations need process isolation or another
  independently enforceable deadline.
- Crash recovery, durable pending state, and startup ordering are
  failure-injection and portable process tested, but still require native
  OpenBSD daemon and supervisor coverage.
- The audit journal is not hash-chained or signed and therefore is not yet
  tamper-evident against a privileged local attacker.
- Journal rotation is not implemented; reaching 16 MiB safely stops further
  preparation and requires administrator handling.
- Admitted connections still consume journal capacity at the configured bounded
  rate. Journal rotation and quota policy remain necessary; the global limiter
  can also let one socket-reachable client temporarily exhaust the shared
  admission budget.
- Stop requests are cooperative and never interrupt an in-flight firewall
  transaction. Supervisor hard-stop deadlines must accommodate the maximum
  authorization, probe, confirmation, commit, and rollback path.
- The signal bridge must start before any other daemon thread and stop on its
  starting thread. The portable lifecycle tests do not replace native OpenBSD
  supervisor and startup-order integration coverage.
- A committed activation whose response is lost is intentionally not rolled
  back. Operation-result lookup and client reconciliation are still required to
  prevent blind replay after an ambiguous response.
- Revision retention and storage-capacity policy are not implemented yet.
- Native validation and revision copying open the candidate separately. The
  private controller-owned staging directory currently prevents unprivileged
  replacement; descriptor-based binding or content digests remain future
  hardening options.
- Native revalidation and activation also open the revision by pathname at
  different moments. Owner-read-only files in a private controller directory
  reduce accidental replacement, but descriptor binding or content digests are
  still required hardening against a compromised controller identity.
- The pending transaction is strictly parsed and private but not signed. A
  compromised controller identity or root can alter both state and revisions;
  content digests or signatures remain future tamper-evidence work.
- Package signing, reproducible-build goals, and key custody require a release
  threat model.

This document will evolve with every new trust boundary or privileged action.
