# Structured event format

Status: **experimental**  
Schema identifier: `gatehold.event.v1`

Gatehold emits single-line JSON objects so operations can be correlated across
the CLI, API, controller, validation helpers, and future Insight analysis.

## Core fields

| Field | Purpose |
|---|---|
| `schema` | Event format version |
| `timestamp` | UTC occurrence time in an ISO 8601 representation |
| `severity` | `debug`, `info`, `warning`, `error`, or `critical` |
| `event_id` | Stable identifier for the event class, such as `GH-PF-1042` |
| `component` | Emitting component |
| `operation_id` | Correlates all stages of one requested operation |
| `action` | Machine-readable action name |
| `outcome` | Machine-readable result |
| `message` | Short operator-facing explanation |
| `attributes` | Structured, event-specific string fields |

Example:

```json
{"schema":"gatehold.event.v1","timestamp":"2026-09-18T12:00:00Z","severity":"warning","event_id":"GH-PF-1042","component":"config-controller","operation_id":"op-7d2140","action":"pf.ruleset.validate","outcome":"rejected","message":"Native PF validation failed; no change was applied.","attributes":{"revision":"38","stage":"native-validation"}}
```

## Redaction

The prototype replaces attribute values with `[REDACTED]` when the key contains
common sensitive fragments such as `password`, `secret`, `token`, `api_key`,
`private_key`, `cookie`, or `authorization`, case-insensitively.

This safeguard does not make arbitrary text safe. Components must not put raw
credentials, private keys, session data, authorization headers, packet payloads,
or unreviewed request bodies into messages or attributes. Later schema-specific
field allowlists will strengthen this boundary.

## Stability

The schema is experimental. Before external consumers depend on it, Gatehold
will define required-field validation, timestamp generation, maximum sizes,
event-ID ownership, retention classes, transport behavior, and compatibility
rules.

