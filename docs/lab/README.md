# Gatehold test lab

The lab will provide a reproducible and isolated environment for destructive
network tests. It must never route experimental policy into a production
network by accident.

The first topology will contain:

- a simulated WAN network;
- an OpenBSD Gatehold VM with separate WAN and LAN interfaces;
- a LAN client used to test DHCP, DNS, routing, and filtering;
- a management path that remains distinct from tested data paths;
- snapshots or repeatable provisioning for rapid reset.

Planned automation commands include `lab-reset`, `lab-deploy`, `lab-test`, and
`lab-report`. These names document the intended workflow; they are not yet
implemented.

