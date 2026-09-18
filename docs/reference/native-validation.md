# Native PF validation

Status: **experimental**

Gatehold's native validator performs syntax checking only. It does not activate
or replace the running PF ruleset.

## Production command boundary

The production executable defaults to the absolute path `/sbin/pfctl`. The
arguments are passed separately:

```text
argv[0] = /sbin/pfctl
argv[1] = -nf
argv[2] = /absolute/staging/root/<operation-id>.pf.conf
```

No shell parses these values. `PATH` is not used to locate the executable.

## Staging rules

- root path is absolute;
- root is an actual directory owned by the controller user;
- root is not group/world writable;
- operation ID is 1–64 ASCII letters, digits, dots, underscores, or hyphens and
  begins with a letter or digit;
- maximum candidate size is 1 MiB;
- NUL bytes are rejected;
- files are created with exclusive, no-follow semantics and mode `0600`;
- a candidate cannot overwrite another candidate with the same operation ID.

## Result states

| Status | Event ID | Meaning |
|---|---|---|
| `staged` | `GH-STAGE-0001` | Candidate was durably written |
| invalid operation ID | `GH-STAGE-1001` | Identifier failed the path-safe policy |
| invalid content | `GH-STAGE-1002` | Candidate was too large or contained NUL |
| unsafe root | `GH-STAGE-1003` | Staging root failed ownership or mode checks |
| already exists | `GH-STAGE-1004` | Operation ID is already in use |
| staging I/O error | `GH-STAGE-2001/2002` | Creation or persistence failed |
| native valid | `GH-PF-0001` | `pfctl -nf` exited successfully |
| unsafe candidate | `GH-PF-1001` | Candidate path or file failed safety checks |
| native rejected | `GH-PF-1002` | `pfctl -nf` returned a nonzero syntax result |
| execution error | `GH-PF-2001` | Validator could not be executed or supervised |
| timeout | `GH-PF-2002` | Validator exceeded the configured deadline |

Standard output and standard error are captured for diagnosis, with a maximum
of 64 KiB per stream. Truncation is recorded explicitly. These fields can
contain network configuration details and must pass support-bundle privacy
processing before export.

Gatehold can convert the result into a `gatehold.event.v1` audit event containing
the event ID, operation ID, revision, outcome, exit code, and truncation flag.
Captured native output is deliberately not copied into that event by default;
it remains separate diagnostic material with a stricter privacy boundary.

## Test boundary

Portable CI uses a purpose-built fake `pfctl` executable to verify argument
passing, accepted/rejected outcomes, timeout termination, output capture, and
output limits. That proves Gatehold's process behavior, not OpenBSD PF syntax.
Release qualification requires a native OpenBSD test using `/sbin/pfctl`.
