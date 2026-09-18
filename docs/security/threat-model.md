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
| Administrator lockout | Confirmed commit, independent timer, management-path probe, automatic rollback |
| Partial multi-service change | Staging, ordered activation, operation journal, compensating rollback |
| API compromise leading to root | Process separation and narrow local controller protocol |
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
- redacts diagnostic attribute values when their keys indicate common secret
  categories.

It does **not** yet guarantee native PF syntax validity, safe activation,
authorization, persistence, rollback, audit durability, or update integrity.

## Residual risks and open work

- Native OpenBSD validation and process-execution code do not exist yet.
- The initial renderer supports only a small rule subset and needs property and
  fuzz testing before consuming persisted input.
- Attribute-key redaction is defense in depth, not proof that a free-text message
  contains no secret; callers need structured allowlisted fields.
- The local controller protocol and authentication mechanism remain to be
  designed.
- Crash recovery and durable transaction journals remain to be designed and
  failure-injection tested.
- Package signing, reproducible-build goals, and key custody require a release
  threat model.

This document will evolve with every new trust boundary or privileged action.

