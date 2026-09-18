# Security design

Gatehold is security-sensitive infrastructure. This section will contain the
threat model and the engineering controls used to keep configuration changes
authorized, observable, verifiable, and recoverable.

Initial topics:

- assets, actors, entry points, and trust boundaries;
- least-privilege process and filesystem design;
- controller authorization and local IPC authentication;
- configuration validation and confirmed commits;
- audit integrity, log retention, and secret redaction;
- update signing and dependency provenance;
- support-bundle privacy;
- safe failure and recovery behavior;
- AI-assisted analysis boundaries.

The root rule is: an instruction to achieve an outcome does not grant arbitrary
permission to change the system.

