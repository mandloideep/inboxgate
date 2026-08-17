# Configuration

InboxGate configuration schema v1 is a strictly validated YAML file containing non-secret policy and limits.
Validation does not contact a service, activate a capability, or read the value of an environment variable named in YAML.

## Validate a file

Pass the configuration path before the command:

```sh
inboxgate --config /path/to/config.yaml config validate
```

The equivalent `--config=/path/to/config.yaml` form is supported.
When the flag is absent, InboxGate uses an explicitly set `INBOXGATE_CONFIG` value and then `/etc/inboxgate/config.yaml`.
Empty path values are rejected.

Success exits 0 and prints `configuration valid`.
Invalid configuration or an unreadable file exits 1 with value-safe diagnostics.
Command misuse exits 2 with focused usage.

The repository's [complete example](../config.example.yaml) contains every schema v1 field and its compiled default.
It validates without any named secret variable being present:

```sh
go run ./cmd/inboxgate --config config.example.yaml config validate
```

## Secret boundary

Fields ending in `_env` contain only an environment-variable name matching `[A-Z_][A-Z0-9_]{0,127}`.
They never contain a credential, token, key, or endpoint value.
The validate command checks only the name and does not look up the named variable.

Do not commit a production configuration.
Sender rules, schedules, and retention policy can reveal private operational information even when the file contains no secret values.

## Strict YAML subset

The file must be one non-null UTF-8 mapping document of at most 65,536 bytes.
The root requires only unquoted integer `version: 1`; omitted supported fields receive the defaults in `config.example.yaml`.
Explicit zeroes, empty strings, empty lists, and `false` remain explicit and are validated rather than replaced by defaults.

The parser rejects unknown or duplicate keys at every level, nulls, non-string keys, multiple documents, document-end markers, directives, anchors, aliases, merge keys, custom tags, templates, includes, substitutions, and regular expressions.
Mappings and sequences are limited to depth 8, counting the root as depth 1, and the decoded tree is limited to 4,096 nodes.
Booleans must be unquoted lowercase `true` or `false`.
Integer fields must be unquoted canonical unsigned decimal values.
Durations use Go duration syntax and must also satisfy the documented field bounds.

## Supported policy bounds

- `server.listen` accepts a hostname, IPv4 address, or bracketed IPv6 address followed by a numeric port, without whitespace, controls, backslashes, or URL components.
- Server timeouts, request size, database connection limits, Gmail pagination, account concurrency, excerpt size, and thread size are bounded as annotated in `config.example.yaml`.
- Gmail scope is exactly `gmail.readonly`.
- Backfill lookbacks, page size, timezone, and run window are validated even when backfill is disabled.
- Gate labels, Gmail categories, sender domains, and literal subject terms have fixed list and item limits.
- Sender allow and block domains must be disjoint.
- Review page sizes and retention periods have bounded cross-field relationships.
- The MCP path is a clean absolute ASCII HTTP path using unescaped RFC 3986 `pchar` characters and `/` separators, without whitespace, controls, backslashes, percent escapes, queries, fragments, repeated slashes, or dot segments.
- Logging level and format use fixed enumerations.
- Policy booleans are parsed only as policy in this slice and do not activate MCP, Gmail, database, review, or task behavior.
- A generic `capabilities` mapping is rejected until the typed capability registry is implemented.

See [product specification section 7](product-specification.md#7-configuration-model) for the complete schema defaults and validation contract.
