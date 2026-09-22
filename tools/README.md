# Development tools

This directory will contain reproducible scripts for build, lab deployment,
testing, report generation, packaging, and release verification.

Tools must default to safe behavior, identify their exact target, and refuse to
operate when a target is ambiguous. Destructive lab-reset operations require a
validated lab identifier and must never accept a broad path or host target.

The first executable lab workflow is the guarded OpenBSD
[service lifecycle harness](../docs/lab/openbsd-service-lifecycle-test.md). It
lives below `tests/openbsd` because it is an assertion-oriented native
integration test rather than a provisioning or deployment tool.
