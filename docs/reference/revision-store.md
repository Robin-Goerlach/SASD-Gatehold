# Revision store

Status: **experimental**

The revision store preserves a PF configuration only after native validation
succeeds. Stored revisions are inputs for future activation and rollback; they
are not evidence that a revision has ever been active.

## Files

Revision 42 is stored as:

```text
00000000000000000042.pf.conf
```

Properties:

- positive 64-bit revision number;
- deterministic fixed-width filename;
- maximum content size of 1 MiB;
- private regular source and destination files;
- exclusive, no-follow creation with owner-read-only mode `0400`;
- file and directory synchronization before success;
- no overwrite or mutation through the Gatehold API.

## Last known good

The `last-known-good` file contains one decimal revision followed by a newline.
Gatehold accepts it only when it is a private regular file owned by the
controller identity and references an existing valid revision.

Updating it creates and synchronizes a private temporary file, then uses an
atomic rename and synchronizes the directory. A hostile symlink at the marker
path is replaced as a directory entry; its target is not followed or modified.

The preparation service never calls this operation. A future activation service
may advance the marker only after the new revision is active, health checks have
passed, and required confirmation has been received.

## Result identifiers

| Event ID | Meaning |
|---|---|
| `GH-REV-0001` | Immutable revision stored |
| `GH-REV-0002` | Revision loaded |
| `GH-REV-0003` | Last-known-good marker updated |
| `GH-REV-0004` | Last-known-good marker resolved |
| `GH-REV-1001` | Invalid revision number |
| `GH-REV-1002` | Unsafe revision root |
| `GH-REV-1003/1007` | Unsafe candidate or revision file |
| `GH-REV-1004` | Revision exceeds size limit |
| `GH-REV-1005` | Immutable revision already exists |
| `GH-REV-1006` | Revision not found |
| `GH-REV-1008/1009` | Marker missing, unsafe, malformed, or dangling |
| `GH-REV-2001`–`2007` | Read, write, or synchronization failure |

The store currently relies on filesystem ownership and permissions. Content
digests, signatures, retention, capacity monitoring, and privileged recovery
procedures remain future work.
