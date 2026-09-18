# AGENTS.md

This file defines repository-wide guidance for coding agents and contributors.

## Project purpose

SASD Gatehold is an OpenBSD-native firewall and secure-routing platform. The
project is security-sensitive. Correctness, reviewability, least privilege,
diagnostics, and safe rollback take precedence over implementation speed.

## Engineering rules

- Keep the OpenBSD base system as close to upstream as possible.
- Prefer native OpenBSD facilities such as PF, `pfctl`, `rcctl`, `syslog`,
  `unveil`, and `pledge` instead of reimplementing them.
- Do not build shell command strings from untrusted input.
- Validate generated configuration with the native tool before activation.
- Preserve the last known-good configuration and provide automatic rollback.
- Keep privileged processes small and expose narrowly scoped operations.
- Never log passwords, private keys, session secrets, API tokens, packet
  payloads, or other credentials.
- Use stable event identifiers and correlation IDs for diagnosable operations.
- Add or update tests for every behavior change.
- Keep documentation in sync with code and clearly distinguish implemented
  features from planned features.

## C++ conventions

- Use modern, portable C++ with RAII and explicit ownership.
- Avoid undefined behavior and unsafe lifetime assumptions.
- Prefer value types and standard-library facilities.
- Treat compiler warnings as defects.
- Avoid introducing a dependency unless it clearly reduces risk or maintenance.
- Public API belongs below `include/gatehold`; implementation belongs in `src`.

## Change discipline

Each security-relevant change should describe:

1. the threat or failure mode addressed;
2. the privilege boundary involved;
3. validation before activation;
4. verification after activation;
5. rollback behavior;
6. logging and redaction behavior;
7. automated and manual tests.

The governing principle is: **a requested goal is not authorization**.

