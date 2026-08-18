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

## Inspect effective policy

Use the same path selection rules with `config effective` to inspect the complete validated policy after compiled defaults are applied:

```sh
inboxgate --config /path/to/config.yaml config effective
```

Success exits 0, leaves stderr empty, and writes one indented JSON document followed by exactly one newline.
Invalid configuration or an unreadable file exits 1 with the same value-safe diagnostics as `config validate` and no partial JSON.
Command misuse exits 2 with focused usage.
A stdout write failure exits 1 with a generic error that does not include configuration data.

The versioned JSON envelope has these top-level fields in this exact order:

1. `output_version`, which is integer `2`.
2. `path_source`, which is `flag`, `environment`, or `default`.
3. `configuration`, which contains every schema v1 field in example-schema order.
4. `sources`, which mirrors the complete configuration hierarchy.

The command never prints the selected filesystem path.
Every leaf in `sources` is `file` when that exact leaf appeared in YAML or `compiled_default` when it was omitted and obtained from `config.Defaults()`.
An explicit value remains `file` even when it equals the compiled default.
An explicitly empty mapping does not change the provenance of omitted children.
Each list has one field-level source rather than one source per element.
Schema v1 has no valid empty-string leaf, so an explicit empty string remains explicit during validation but is rejected without effective JSON.

Durations use the canonical Go duration string after validation.
Integers and booleans remain JSON numbers and booleans.
Empty lists are `[]` rather than `null`.
Accepted string spelling and list order are preserved.
Comments, YAML key order, scalar quoting, and an optional document-start marker do not affect the output.
Repeated runs over the same configuration bytes, path-selection class, and binary version produce byte-identical stdout.

Fields ending in `_env` still contain environment-variable names only.
The effective command prints those names as policy but never reads, substitutes, hashes, measures, checks the presence of, or otherwise represents the named values.
The only environment lookup is `INBOXGATE_CONFIG` for file selection.

Effective output can still reveal operationally sensitive policy such as sender domains, subject terms, bind addresses, schedules, retention choices, and environment-variable names.
Review it before pasting it into public issues, logs, or chat systems.
The command is a local read-only inspection surface and does not start Gmail, OAuth, Turso, MCP, HTTP, backfill, review, logging, encryption, or task behavior.

Output version 2 adds the typed `capabilities` section immediately after `version` in both `configuration` and `sources`.
The section has the same complete five-field shape whether its values came from YAML or compiled defaults.

## Inspect capabilities

Use `capabilities` with the same global path selection rules:

```sh
inboxgate --config /path/to/config.yaml capabilities
```

The command strictly validates the configuration before it prints one deterministic indented JSON document followed by exactly one newline.
The envelope orders `output_version`, `configuration_schema_version`, and `capabilities`.
Capability entries are sorted by bytewise name and order `name`, `implementation_status`, `configuration_status`, `enabled`, `required_secret_names`, `required_database_migration`, and `security_classification`.

`implementation_status` is compile-time truth and is either `implemented` or `not_implemented`.
`configuration_status` is validated policy and is `enabled`, `disabled`, or `not_configurable`.
`enabled` is true only when behavior is implemented and its configuration status is `enabled` or `not_configurable`.
A not-implemented capability can never be enabled.

Schema v1 allows only `gmail.read`, `gmail.current_sync`, `gmail.backfill`, `mail.review_read`, and `mail.review_write` under the top-level `capabilities` mapping.
Each field defaults to `false`.
An explicit `false` is accepted and remains file-sourced in effective output.
An explicit `true` fails closed until that behavior is implemented by the binary.
Prohibited, excluded, misspelled, and arbitrary capability keys are rejected.
Subordinate policy such as `backfill.enabled` and `mcp.enabled` cannot bypass a disabled top-level capability gate.

`required_secret_names` contains sorted validated environment-variable names only.
The command never reads, checks, hashes, measures, or derives information from the named values.
`required_database_migration` is null until a capability that needs durable state registers an exact migration identifier.
The selected configuration path, path-source class, timestamps, host state, service connectivity, secret presence, and account state are omitted.
Review capability output before sharing it because environment-variable names can reveal operational naming conventions.
The command starts no service and grants no Gmail, OAuth, database, MCP, review, or provider authority.

## Check local service construction

Use `doctor` with the same global configuration path rules:

```sh
inboxgate --config /path/to/config.yaml doctor
```

The command strictly validates the selected file and constructs the configured logger, readiness state, bounded health handler, and HTTP server without binding a socket.
It does not perform a bind feasibility check, read any YAML-named environment variable, contact a provider or database, or start Gmail, OAuth, MCP, scheduler, review, or backfill behavior.
Success exits 0, leaves stderr empty, and prints a deterministic versioned JSON result with passing `configuration` and `service_runtime` checks.
Invalid configuration exits 1 with the same value-safe diagnostics as `config validate` and no partial JSON.
Command misuse exits 2 with focused usage.

## Run process-health serving

Start the bounded process-health service with:

```sh
inboxgate --config /path/to/config.yaml serve
```

The command validates configuration before making one attempt to bind `server.listen`.
It writes no normal output to stdout.
Lifecycle and request records go to stderr through the configured `log/slog` JSON or text handler at the configured minimum level.
Logs use bounded event, operation, method, outcome, status, and duration fields and omit paths, queries, listener addresses, configuration paths, headers, bodies, remote addresses, host values, secret names and values, account data, and provider data.

The service exposes only `GET` and `HEAD` on `/health/live` and `/health/ready`.
Only those literal escaped paths are accepted, so percent-encoded alternate spellings receive the fixed `404` response.
Liveness reports fixed process health.
Readiness is true only while the configured logger and server are constructed, the TCP listener exists, the serving lifecycle is active, and shutdown has not begun.
Readiness does not claim database, migration, scheduler, account, Gmail, OAuth, provider, or MCP availability.
Every response is fixed and bounded, disables caching and content-type sniffing, and uses JSON representation headers.
Other methods receive `405`, unknown paths receive `404`, declared oversized health bodies receive `413`, and every other declared or transfer-encoded health body receives `400` without being read.

The configured `server` timeouts and request limit apply to this runtime.
HTTP headers have a compiled 16 KiB limit.
The listener admits at most a compiled 128 accepted connections concurrently, and it does not accept another connection into application work until an existing accepted connection closes.
The first `SIGINT` or `SIGTERM` makes readiness false and gives active requests up to a compiled 10 seconds to drain.
A second signal does not restart or extend that deadline.

The default `0.0.0.0:8080` listener covers every host interface and is not authorization for public exposure.
Bind only to an approved private interface, protect the listener with an appropriate firewall, or publish the probes through an approved private reverse-proxy path.
This repository does not yet provide TLS termination, deployment configuration, authenticated diagnostics, MCP transport, or any public REST API.

## Enroll one Gmail account

`inboxgate account add` is a one-shot operator command that binds the validated `server.listen` address, prints one bounded authorization URL, accepts one exact callback at `/oauth/google/callback`, and exits after durable reconciliation.
It resolves only the environment variables named by the validated Gmail, database, and encryption fields.
It accepts no credential argument and never adds OAuth routes to `serve`.
HTTP callback URIs are accepted only for credential-free literal-loopback tests, while normal runtime input requires HTTPS.
Live authorization and live Turso access remain prohibited until the owner completes the later approval and runtime-activation checkpoints.

`inboxgate account list`, `account pause`, `account resume`, and confirmed `account revoke` are one-shot operator commands over the typed account lifecycle boundary.
They accept no credential argument, keep Turso execution restricted to credential-free literal-loopback endpoints, and never add an operator route to `serve`.
List, pause, and resume resolve only the selected database URL and optional token environment names.
Revocation resolves the selected encryption key only after a durable revoked-attempting claim and a fresh encrypted-credential read are proved, then makes at most one bounded request to the fixed Google revocation authority.
Account IDs in list output are sensitive and must not be pasted into public diagnostics or review systems.

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
- The `capabilities` mapping accepts only the five false-by-default gates documented above.
- A true value is rejected until the corresponding binary behavior is implemented.

See [product specification section 7](product-specification.md#7-configuration-model) for the complete schema defaults and validation contract.
