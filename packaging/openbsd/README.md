# OpenBSD packaging

This directory is reserved for native OpenBSD package metadata, installation
scripts, service definitions, and release tooling.

Production appliances will install versioned and signed packages. They will not
build from a Git checkout and will not require Git, Node.js, compilers, or
development tooling.

The experimental `gateholdd` executable intentionally stays in the foreground
so a future OpenBSD `rc.d` script can supervise it directly. Package scripts
must create separate private journal, revision, transaction, and socket
directories plus dedicated controller and API identities. No `rc.d` definition
is shipped yet; the current daemon is for isolated integration labs only.
