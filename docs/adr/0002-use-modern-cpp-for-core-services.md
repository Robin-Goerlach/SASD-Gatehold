# ADR-0002: Use modern C++ for core services

- Status: accepted
- Date: 2026-09-18

## Context

The controller, command-line client, and portable domain logic require a native
implementation with predictable deployment on OpenBSD, minimal runtime
dependencies, explicit resource ownership, and good testability. The project
also needs to keep the final appliance free of compilers and development
runtimes.

## Decision

Gatehold core services will be written in modern C++. The current baseline is
C++23, subject to the compiler support of the oldest OpenBSD release supported
by Gatehold. CMake and CTest provide the portable build and test entry points.

Code will favor RAII, value types, immutable input where practical, explicit
ownership, and standard-library facilities. External dependencies require a
documented security, licensing, portability, and maintenance justification.

## Consequences

- The project can build small native executables and packages.
- Compiler warnings, sanitizers, static analysis, fuzzing, and native regression
  tests become essential controls.
- C++ memory-safety hazards must be actively designed and tested against.
- Language-version use may be limited when OpenBSD's supported toolchain lags.
- The web interface may use separately built static assets, but Node.js is not a
  production requirement.

## Security impact

Privileged C++ code must remain minimal. Parsers and protocol boundaries receive
negative tests and fuzzing. Undefined behavior, lifetime ambiguity, unchecked
integer conversion, and shell-mediated execution are treated as security bugs.

## Alternatives considered

- Go offered fast service development and simple deployment but did not match
  the selected C++ product direction.
- C would integrate naturally with the base system but increase the amount of
  manual ownership and error handling.
- C# would add a runtime and a less conventional OpenBSD deployment path for the
  privileged core.

