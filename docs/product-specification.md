# Mail Hub Agent Implementation Specification

Status: ready for implementation planning.

This document is a self-contained handoff for an implementation agent.
It defines the current minimum product and supersedes earlier private planning notes where they differ.
It does not authorize deployment, account access, OAuth consent, secret creation, or production writes without the owner's explicit approval.

## 1. Product name

The recommended public project name is **InboxGate**.
The recommended repository slug is `inbox-gate` and the recommended Go module suffix is `/inbox-gate`.

InboxGate describes the product's most important job.
It is a controlled gate between large email accounts and expensive or tool-capable AI agents.
It does not imply that the service replaces Gmail or sends mail.

Reasonable alternatives are listed below.

| Name | Repository slug | Character |
| --- | --- | --- |
| InboxGate | `inbox-gate` | Clear and security-oriented |
| MailIntake | `mail-intake` | Plain and infrastructure-oriented |
| InboxRouter | `inbox-router` | Emphasizes classification and delivery |
| MailTriage | `mail-triage` | Emphasizes review workflow |
| InboxLoom | `inbox-loom` | Distinctive and product-oriented |
| MailHub | `mail-hub` | Familiar but generic |

The owner must check repository, package, trademark, and domain availability before publishing.
The implementation must not depend on the final product name.
Use `internal` packages and neutral domain names so the binary and module can be renamed before the first public release.

## 2. Objective

Build a small Go service that connects many Gmail and Google Workspace accounts, synchronizes email incrementally, performs a deterministic low-cost gate, and exposes a bounded review surface to Hermes through MCP.

Hermes will use its existing model to review candidate email and decide whether it represents no action, a review item, or a task proposal.
Hermes will use a separate Vikunja integration to create and manage approved tasks.

The service must support historical backfill without sending every message to a model.
The service must remain recoverable if the Hetzner VM is lost.
The service should be suitable for eventual open-source release.

## 3. Scope lock for the first release

The first release includes only the following capabilities.

- Gmail and Google Workspace accounts through the Gmail REST API.
- Multiple independently authorized Google accounts.
- Read-only Gmail permissions.
- Metadata-first current-mail synchronization.
- Resumable historical backfill.
- Deterministic gating with no model call.
- Durable state in Turso.
- A versioned, strictly validated YAML configuration file for non-secret policy.
- A machine-readable inventory of implemented and enabled capabilities.
- A private streamable HTTP MCP endpoint for Hermes.
- Operator commands for OAuth enrollment, synchronization, backfill, and diagnostics.
- Health and readiness endpoints.
- Structured audit events.
- Unit, integration, contract, and end-to-end tests.

The first release explicitly excludes the following capabilities.

- A web dashboard.
- A general public REST API.
- Zoho Mail.
- Microsoft Outlook or Exchange.
- Sending, replying, forwarding, archiving, deleting, labeling, or marking Gmail messages read.
- Downloading attachments.
- Persisting raw MIME messages.
- Running a local Ollama worker.
- Pub/Sub push notifications.
- A general queue broker.
- A workflow engine.
- Direct Vikunja API calls from InboxGate.
- Direct A2A implementation inside InboxGate.
- Multiple human users or tenant administration.

Any proposed change to this scope must first include a failing acceptance test that demonstrates a current requirement which cannot be satisfied otherwise.

## 4. Engineering principles

### 4.1 TDD

Every production behavior begins with a failing test.
The implementation sequence is red, green, and refactor.
Do not write speculative production abstractions before their first consuming test.

Test behavior through public package boundaries whenever practical.
Use small unit tests for deterministic logic and integration tests for storage, OAuth HTTP exchanges, Gmail HTTP exchanges, and MCP transport.
Use an end-to-end test for the complete path from a fake Gmail server to an MCP result.

### 4.2 YAGNI

Implement only the current Gmail-first product.
Do not build a generic provider framework until the second provider is approved.
Do not build a plugin system.
Do not build a generic protocol gateway.
Do not build a UI.
Do not build direct A2A support.

Keep seams where tests or security boundaries require them.
Avoid interfaces that have only one implementation unless the interface is owned by the consuming package and materially improves tests.

### 4.3 Minimal dependencies

Prefer the Go standard library.

The initial direct dependency budget is limited to four packages.

- `golang.org/x/oauth2` for standards-compliant OAuth token handling.
- The official Model Context Protocol Go SDK for MCP protocol handling.
- `turso.tech/database/tursogo-serverless` for remote access to the Turso Database rewrite through `database/sql` behind the repository-owned adapter.
- `go.yaml.in/yaml/v3` for the human-editable configuration file until YAML v4 has a stable release.

Pin exact versions in `go.mod` and commit `go.sum`.
The implementation agent must verify the selected versions, licenses, checksums, advisories, and complete transitive dependency graph before the first merge.
`turso.tech/database/tursogo-serverless` v0.0.0-20260817073220-04ff3de5e1a8 was evaluated and rejected by [ADR 0003](adr/0003-turso-serverless-driver-contract.md).
[ADR 0004](adr/0004-turso-serverless-adapter.md) accepts the newer exact version v0.0.0-20260817122138-24adc316cdc4 behind the repository-owned adapter with the unresolved risks in the [known-risk register](known-risks.md).
The adapter decision does not claim that those risks are fixed or that runtime activation, credentials, remote execution, or production use are ready.

Do not use `github.com/tursodatabase/libsql-client-go` for a new database.
The current Turso documentation assigns it to remote legacy libSQL databases rather than new databases using the Turso rewrite.
Do not use `github.com/tursodatabase/go-libsql` because the first release does not need an embedded replica and should avoid CGO and native libraries.
If the owner already created a legacy libSQL database instead of a new Turso Database, stop and document the compatibility choice before changing the driver.

Do not add a web framework, router, ORM, query builder, migration framework, dependency-injection framework, configuration library, logging framework, assertion library, mocking framework, queue library, scheduler library, or generated Gmail SDK.

Use `net/http`, `encoding/json`, `database/sql` when supported by the selected driver, `log/slog`, `flag`, `context`, and `testing`.
Use handwritten Gmail REST requests and response types for only the fields required by the tests.
Use embedded numbered SQL migration files and a small migration runner.

Every new dependency requires a short architecture decision record containing the need, alternatives considered, transitive dependency impact, license, maintenance status, and removal plan.

### 4.4 Open-source readiness

Use a permissive project license selected by the owner before publication.
Do not copy secrets, account identifiers, private domains, email addresses, message content, Tailscale names, or production URLs into source, tests, fixtures, logs, or documentation.
Use synthetic fixtures.
Provide `SECURITY.md`, `CONTRIBUTING.md`, a threat model, and a sample environment file before the first public release.

## 5. Architecture decision

InboxGate is a deterministic email service, not an autonomous agent.
It will expose MCP to Hermes.
Hermes already provides A2A for communication with other agents.

The initial protocol path is therefore:

```text
Telegram or Hermes CLI
        |
        v
Hermes agent
        |
        +---- MCP ----> InboxGate
        |
        +---- MCP or scoped skill ----> Vikunja
        |
        +---- A2A ----> another Hermes agent, when needed
```

Do not implement A2A inside InboxGate.
Doing so would turn a deterministic data service into a second agent runtime and duplicate Hermes behavior.

If a future non-Hermes consumer requires direct A2A access, implement a separate adapter process after a concrete acceptance test exists.
That adapter should call the same application use cases as MCP and must not receive broader permissions.

The phrase `A2P` in earlier discussion is interpreted as `A2A`, the Agent2Agent protocol.

## 6. Process model

The first release is one Go binary with explicit subcommands.

```text
inboxgate serve
inboxgate account add
inboxgate account list
inboxgate account revoke
inboxgate sync run
inboxgate backfill start
inboxgate backfill status
inboxgate config validate
inboxgate config effective
inboxgate capabilities
inboxgate doctor
inboxgate migrate
```

The completed first-release `serve` command will run the private MCP endpoint, health endpoints, OAuth callback endpoint, and internal poll scheduler.
The current service slice registers only fixed process-health endpoints and deliberately does not register MCP, OAuth, scheduler, database, or provider behavior.
The other subcommands are operator surfaces and reuse the same application use cases.
The local `capabilities` command is available before `serve` and loads inert validated policy without starting any runtime component.
The local `doctor` command validates configuration and constructs the logger, readiness state, health handler, and bounded HTTP server without binding a listener.
The future MCP `system_capabilities` tool adapts the same typed registry.

Do not create separate server and worker binaries in the first release.
Do not add a distributed worker until current synchronization and backfill cannot meet measured requirements inside one process.

## 7. Configuration model

InboxGate uses one versioned YAML configuration file for non-secret product policy and runtime behavior.
The recommended production path is `/etc/inboxgate/config.yaml`.
The binary accepts a different path through `--config` or the `INBOXGATE_CONFIG` environment variable.

The public repository contains `config.example.yaml` with safe defaults and explanatory comments.
The production configuration is not committed to a public repository because sender rules, account policy, schedules, and retention choices may still reveal private information.

### 7.1 Configuration and secret boundary

The YAML file may contain the following categories.

- Listening address and non-secret HTTP limits.
- Polling cadence, jitter, pagination, concurrency, and retry limits.
- Default and maximum historical backfill windows.
- Backfill run schedule and timezone.
- Deterministic gate rules.
- Body excerpt and result-size limits.
- Review behavior and pagination limits.
- Retention periods.
- Explicitly enabled implemented capabilities.
- Names of environment variables that contain secrets.

The YAML file must never contain the following values.

- Google OAuth client secret.
- Gmail refresh token or access token.
- Turso database authentication token.
- MCP bearer token.
- Application encryption master key.
- Tailscale authentication key.
- Vikunja URL or token unless a future separate adapter explicitly needs them.

Secrets are provided through runtime environment variables or file-based container secrets.
The configuration may name the environment variable to read, but it never receives or prints its value.

### 7.2 Example schema

The committed `config.example.yaml` has this shape and its values are the compiled schema v1 defaults.

```yaml
version: 1

capabilities:
  gmail.read: false
  gmail.current_sync: false
  gmail.backfill: false
  mail.review_read: false
  mail.review_write: false

server:
  listen: "0.0.0.0:8080"
  read_header_timeout: 5s
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 60s
  max_request_bytes: 1048576

database:
  engine: turso
  url_env: TURSO_DATABASE_URL
  auth_token_env: TURSO_AUTH_TOKEN
  max_open_connections: 8
  max_idle_connections: 2
  connection_max_lifetime: 30m

gmail:
  oauth_client_id_env: GOOGLE_OAUTH_CLIENT_ID
  oauth_client_secret_env: GOOGLE_OAUTH_CLIENT_SECRET
  oauth_redirect_url_env: GOOGLE_OAUTH_REDIRECT_URL
  scope: gmail.readonly
  poll_interval: 5m
  poll_jitter: 30s
  page_size: 100
  max_accounts_in_flight: 2
  body_excerpt_bytes: 32768
  thread_max_messages: 50

backfill:
  enabled: true
  default_lookback_days: 365
  maximum_lookback_days: 3650
  page_size: 100
  current_mail_has_priority: true
  run_window:
    timezone: America/Chicago
    start: "22:00"
    end: "06:00"

gate:
  version: 1
  excluded_labels:
    - SPAM
    - TRASH
  suppress_gmail_categories:
    - CATEGORY_PROMOTIONS
    - CATEGORY_SOCIAL
  direct_recipient_is_candidate: true
  mailing_list_is_bulk_signal: true
  sender_allow_domains: []
  sender_block_domains: []
  subject_candidate_terms: []
  subject_urgent_terms: []

review:
  default_page_size: 25
  maximum_page_size: 100
  automatic_task_creation: false

retention:
  metadata_days: 0
  excerpt_days: 365
  audit_days: 730

mcp:
  enabled: true
  path: /mcp
  bearer_token_env: INBOXGATE_MCP_TOKEN
  enable_review_writes: true
  enable_operator_tools: false

encryption:
  master_key_env: INBOXGATE_MASTER_KEY

logging:
  level: info
  format: json
```

`metadata_days: 0` means metadata is retained until the owner explicitly changes policy.
It does not mean metadata is deleted immediately.

The default backfill is one year and the maximum single requested lookback is ten years.
An operator can choose a smaller range for each account.
Going beyond the configured maximum requires changing the file, validating it, restarting the service, and issuing a new bounded backfill command.

### 7.3 Validation rules

Configuration is decoded into typed Go structures.
Unknown keys, duplicate keys, missing required fields, invalid durations, invalid timezones, unsafe paths, unsupported versions, and values outside documented bounds are fatal startup errors.

The parser must reject YAML anchors, aliases, custom tags, and multiple documents.
The configuration file has a small fixed maximum size and nesting depth.
These restrictions keep YAML a human-friendly syntax without accepting its most complex features.

Schema v1 requires exactly one non-null UTF-8 mapping document no larger than 65,536 bytes.
It allows comments and one optional document-start marker.
It rejects additional documents, document-end markers, directives, anchors, aliases, merge keys, custom tags, explicit nulls, non-string keys, unknown keys, duplicate keys, NUL, and disallowed control characters before typed decoding.
Mapping and sequence depth is limited to 8, counting the root as depth 1, and the decoded tree is limited to 4,096 nodes.
Booleans are unquoted lowercase `true` or `false`, integer fields are unquoted canonical unsigned decimal values, and durations use `time.ParseDuration` followed by field bounds.
The parser provides no includes, templates, environment substitution, arbitrary unmarshalling hooks, or regular expressions.

`version` is the only required field and must be unquoted integer `1`.
Omitted sections and fields receive the defaults in section 7.2.
Explicit zeroes, empty strings, empty lists, and `false` values are validated and never replaced by defaults.
Explicit null is invalid and every list field permits an empty list.

`server.listen` is a non-empty hostname, IPv4, or bracketed IPv6 `host:port` of at most 263 bytes with numeric port 1 through 65535 and no whitespace, controls, backslashes, malformed host labels, or URL components.
Read-header timeout is 1 second through 30 seconds and cannot exceed read timeout.
Read and write timeouts are 1 second through 5 minutes, idle timeout is 1 second through 10 minutes, and maximum request bytes is 1,024 through 1,048,576.
The database engine is exactly `turso`, open connections are 1 through 64, idle connections are 0 through 64 and cannot exceed open connections, and connection lifetime is 1 minute through 24 hours.

Gmail scope is exactly `gmail.readonly`.
Polling is 1 minute through 1 hour, jitter is 0 through 5 minutes and cannot exceed half the polling interval, page size is 1 through 500, account concurrency is 1 through 16, excerpt bytes is 1,024 through 65,536, and thread messages is 1 through 100.
Backfill lookbacks are 1 through 3,650 days with the default not above the maximum, and backfill page size is 1 through 500.
The run timezone is `UTC` or a loadable safe IANA name of at most 64 ASCII bytes, and its exact zero-padded `HH:MM` start and end must differ.
Both same-day and overnight windows are valid, and disabling backfill does not bypass validation.

Gate version is integer `1`.
Excluded labels contain at most 32 unique `[A-Za-z0-9_-]{1,128}` identifiers.
Suppressed Gmail categories contain at most five unique values from `CATEGORY_FORUMS`, `CATEGORY_PERSONAL`, `CATEGORY_PROMOTIONS`, `CATEGORY_SOCIAL`, and `CATEGORY_UPDATES`.
Sender allow and block lists each contain at most 256 unique lowercase ASCII DNS domains and remain disjoint.
Subject lists each contain at most 256 case-insensitively unique trimmed literal terms of 1 through 128 UTF-8 bytes without controls.
Review page sizes are 1 through 100 with the default not above the maximum.
Metadata retention is 0 or 1 through 36,500 days, excerpt and audit retention are 1 through 3,650 days, and nonzero metadata retention cannot be shorter than excerpt retention.
The MCP path is a clean absolute ASCII HTTP path of 2 through 128 bytes using unescaped RFC 3986 `pchar` characters and `/` separators, and cannot be `/`, contain whitespace, controls, backslashes, repeated slashes, dot segments, percent escapes, a query, or a fragment.
Logging level is `debug`, `info`, `warn`, or `error`, and logging format is `json` or `text`.
Every field ending in `_env` stores only a name matching `[A-Z_][A-Z0-9_]{0,127}`.
The top-level `capabilities` mapping accepts only `gmail.read`, `gmail.current_sync`, `gmail.backfill`, `mail.review_read`, and `mail.review_write`.
All five defaults are false, an explicit false remains file-sourced, and a true value is rejected until that behavior is implemented by the binary.
Unknown, prohibited, excluded, misspelled, and arbitrary capability keys are fatal validation errors.
Other policy booleans do not activate runtime behavior during validation and cannot bypass a disabled capability gate.

Do not support regular expressions in the first gate configuration.
Use normalized exact addresses, domain suffixes, header signals, and case-insensitive literal terms.
This avoids regular-expression denial of service and makes rule behavior explainable.
Subject terms are signals only and cannot produce an urgent decision without another trusted signal.

`inboxgate config validate` parses and validates the file without contacting Google or Turso.
The global `--config PATH` or `--config=PATH` flag must precede the command.
Path precedence is the explicit flag, an explicitly set `INBOXGATE_CONFIG`, and `/etc/inboxgate/config.yaml`.
Empty path values, repeated flags, positional paths, unknown flags, and extra arguments are rejected.
Symlinks to regular files are accepted, while directories, devices, sockets, FIFOs, and other non-regular targets are rejected.
Success exits 0 with exactly `configuration valid` on stdout, invalid configuration exits 1 with value-safe diagnostics on stderr, and CLI misuse exits 2 with focused usage.
Validation never reads an environment variable whose name came from YAML and makes no external request.
`inboxgate config effective` loads and validates the same file, applies the single compiled `config.Defaults()` definition, and prints one deterministic indented JSON document followed by one newline.
It never contacts a service, activates runtime behavior, reads an environment variable named by YAML, or prints the selected configuration path.
Invalid input produces the same value-safe diagnostics as `config validate` and no partial JSON.

The versioned JSON envelope orders `output_version`, `path_source`, `configuration`, and `sources` exactly.
Output version 2 uses `flag`, `environment`, or `default` as the path-selection class without disclosing path data.
Version 2 adds `capabilities` immediately after `version` in both the normalized configuration and provenance objects.
The `configuration` object contains every schema v1 field in section 7.2 order after defaults are applied.
Durations use `time.Duration.String()`, integers and booleans retain their JSON types, empty lists are never null, and accepted string spelling and list order are preserved.
Standard `encoding/json` escaping, `json.MarshalIndent` with two spaces, and one final newline define the serialization.

The `sources` object mirrors the complete configuration hierarchy and uses `file` or `compiled_default` at every leaf.
Provenance comes from YAML presence rather than value comparison, so an explicit default-equivalent value remains `file` and an empty mapping leaves omitted children as `compiled_default`.
List provenance applies to the whole field.
The `version` source is always `file` because schema v1 requires it.

Fields ending in `_env` are printed as validated environment-variable names, but their named values are structurally never acquired or represented.
Successful output may still contain sensitive operational policy, including sender domains, subject terms, bind addresses, schedules, retention choices, and environment-variable names.
Operators must review it before sharing it in public issues or logs.
The command is a local read-only inspection surface and does not expose effective configuration through MCP, HTTP, health endpoints, logs, or an application API.

Configuration is loaded once at process start.
Do not implement hot reload in the first release.
A changed configuration requires validation and a graceful restart.

### 7.4 Implemented versus enabled capabilities

A configuration file cannot activate code that the binary does not implement.

The binary contains a typed capability registry with capability name, implementation status, configuration status, required secret names, required database migration, and security classification.
`inboxgate capabilities` prints that registry as JSON.
The future read-only `system_capabilities` MCP tool must adapt the same registry rather than create another capability model.

The registry contains `gmail.backfill`, `gmail.current_sync`, `gmail.modify`, `gmail.read`, `mail.review_read`, `mail.review_write`, `system.capabilities`, `vikunja.write`, and `zoho.read` in bytewise lexical order.
The local inspection behavior makes only `system.capabilities` implemented in the current binary slice.
Every other entry is not implemented.
`gmail.modify` is prohibited, while `zoho.read` and `vikunja.write` remain visible but not configurable.

Implementation status is compile-time truth and is `implemented` or `not_implemented`.
Configuration status is validated policy and is `enabled`, `disabled`, or `not_configurable`.
Derived enablement is true only for implemented behavior whose configuration status is enabled or not configurable.
It is never true for a not-implemented capability.

The version 1 capability JSON envelope orders `output_version`, `configuration_schema_version`, and `capabilities`.
Each capability orders `name`, `implementation_status`, `configuration_status`, `enabled`, `required_secret_names`, `required_database_migration`, and `security_classification`.
Required secret names are sorted validated environment-variable names only, and their values are never acquired.
Required database migration is null until an exact durable-state migration exists.
The output contains no path data, runtime state, secret presence, provider connectivity, database connectivity, account state, or health state.

Unknown capability keys are validation errors.
Capability inspection loads inert policy only and does not start or grant Gmail, OAuth, Turso, MCP, HTTP, backfill, review, encryption, logging, or provider behavior.
Hermes will be able to inspect capabilities but cannot edit configuration through MCP.

## 8. Package layout

Start with the following small layout and add packages only when a real boundary appears.

```text
cmd/inboxgate/main.go
internal/account/
internal/config/
internal/gmail/
internal/gate/
internal/mail/
internal/store/
internal/mcp/
internal/operator/
internal/httpserver/
internal/cryptobox/
migrations/
testdata/
docs/adr/
```

`internal/mail` owns the normalized message and thread vocabulary.
`internal/config` owns strict YAML decoding, defaults, validation, redacted effective output, and the capability registry.
`internal/gmail` owns Gmail HTTP requests, Gmail response decoding, OAuth provider details, and Gmail cursor behavior.
`internal/gate` owns pure deterministic classification.
`internal/storage` owns typed persistence boundaries and keeps `database/sql`, driver types, and SQL inside replaceable implementations.
`internal/mcp` adapts application use cases to MCP tools.
`internal/operator` adapts application use cases to CLI subcommands.
`internal/httpserver` owns health, readiness, OAuth callback, and MCP transport registration.
`internal/cryptobox` owns authenticated encryption for provider credentials.

Package names describe behavior rather than architectural fashion.
Do not add `domain`, `service`, `repository`, or `utils` packages merely to imitate a layered template.

## 9. Core data model

Use opaque internal identifiers for accounts and records.
Never use a Gmail address as a database primary key.

### 9.1 Accounts

An account record contains the following information.

- Internal account ID.
- Provider value fixed to `gmail` for the first release.
- Stable provider subject ID.
- Display email address encrypted or separately protected according to the final threat model.
- Human-selected display name.
- Encrypted OAuth refresh token material.
- Granted scopes.
- Account state.
- Last successful synchronization time.
- Last error category and time.
- Creation and update timestamps.

Valid account states are `pending`, `active`, `reauthorization_required`, `paused`, and `revoked`.

Migration `0002_accounts_and_sync_cursors.sql` intentionally persists only the internal account ID, fixed `gmail` provider, opaque provider subject, and optional committed Gmail history ID.
All broader account fields and states remain future schema work owned by their vertical slices.
The minimum account ID is exactly 32 lowercase hexadecimal ASCII characters and is generated before storage receives it.
The provider subject is opaque, case-sensitive visible ASCII from 1 through 255 bytes and is never trimmed, case-folded, parsed, logged, or used as the primary key.

Migration `0003_provider_credentials.sql` stores one versioned authenticated ciphertext envelope per account.
It stores only the account ID, envelope key identifier, and ciphertext envelope and never accepts or persists plaintext token bytes.
The envelope and stored key identifier must agree structurally before a storage request is made and again after every database read.

Migration `0004_account_lifecycle.sql` stores one strict versioned lifecycle row per account and creates a pending version 1 row in the same transaction as every later account insert.
It backfills an existing account as active only when both its synchronization cursor and encrypted provider credential exist, and otherwise backfills pending.
The implemented graph is pending to active, active to paused or reauthorization-required, paused to active, and every non-revoked state to revoked-pending, followed by revoked-attempting and then only revoked-confirmed or revoked-manual-action-required.
The exact reauthorization reasons are `refresh_invalid_grant`, `refresh_admin_policy_enforced`, `gmail_unauthorized_after_refresh`, and `gmail_domain_policy`.
Activation and resume require durable cursor and credential presence, every non-idempotent transition increments the version once, and revoked is terminal.

### 9.2 Synchronization cursors

Each account has an incremental Gmail history cursor.
Store the last committed `historyId`, the most recent mailbox time observed, the current synchronization lease, and retry metadata.

The minimum cursor slice stores only a canonical positive uint64 Gmail `historyId` as decimal text.
An absent row means uninitialized, and zero, empty, signed, padded, or out-of-range values are invalid.
Migration `0005_current_discovery_atomic_commit.sql` adds message-coupled current-discovery advancement without adding mailbox times, leases, retry metadata, or stale-cursor state.
The cursor-only commit initializes an absent enrollment cursor and rejects a present cursor or durable current-discovery attempt.

Advance a cursor only in the same transaction that commits the discovered message metadata.
Never advance a cursor after a partial failed page.

The current-discovery storage aggregate accepts one active account, an exact current cursor, a strictly greater next cursor, and at most 5,000 normalized messages.
It sorts messages by Gmail message ID, collapses exact duplicates, rejects conflicting duplicates, and limits the canonical aggregate encoding to 16,777,216 bytes.
It promotes canonical message metadata and advances the cursor through one fixed trigger-backed finalization statement or changes neither.
Every explicit reconciliation completes or safely removes only bounded durable staging without contacting Gmail.

The implemented internal current-discovery invocation reconciles that staging before any OAuth or Gmail request and then requires one exact active lifecycle, cursor, ciphertext credential, authenticated decryption, and unchanged lifecycle version.
It makes one explicit refresh-token exchange through the existing OAuth root package and never retries or automatically refreshes that exchange.
Only exact `invalid_grant`, `admin_policy_enforced`, Gmail 401 after refresh, and an unambiguous Gmail `domainPolicy` reason enter the four existing reauthorization transitions.
Transient, malformed, conflicting, oversized, or unknown provider failures leave lifecycle, credential, messages, and cursor unchanged.

The invocation reads at most ten history pages and 5,000 unique message additions through fixed read-only requests.
It accepts at most 500 history records and 500 additions per page, rejects page-token cycles and conflicting message-thread identities, and uses only the final complete-chain `historyId` as a proposed cursor.
It calls the atomic aggregate exactly once after all non-vanished messages normalize and never calls the cursor-only initialization operation.
Its result contains only bounded counts and a cursor-advanced flag.

If Gmail reports that a history cursor is too old, mark the cursor stale and run bounded reconciliation.
Do not silently restart an unlimited full backfill.
The current inert invocation returns a fixed stale-history category and preserves the active lifecycle and cursor because the schema does not yet contain durable stale status.
Persisted stale status and bounded full reconciliation remain later work before release.

### 9.3 Messages and threads

Store the minimum normalized fields required for gating and review.

- Internal record ID.
- Account ID.
- Gmail message ID.
- Gmail thread ID.
- RFC `Message-ID` when present.
- Internal date.
- Sender display name and address.
- Recipient addresses needed for account context.
- Subject.
- Selected labels.
- Size estimate.
- Attachment-presence flag and attachment metadata count.
- Sanitized bounded text excerpt when fetched.
- Content hash.
- Discovery source and timestamps.

Use `(account_id, gmail_message_id)` as a unique natural key.
Use `(account_id, gmail_thread_id)` for thread grouping.
Never assume a Gmail thread ID is globally unique across accounts.

### 9.4 Gate decisions

Each evaluated message receives a versioned deterministic decision.

Valid outcomes are:

- `ignore`
- `metadata_only`
- `review_candidate`
- `urgent_review_candidate`

Store the gate version, outcome, reason codes, evaluated timestamp, and the input-field hash.
Do not store free-form model prose in this table.
The implemented gate version 1 binds the canonical metadata hash, both gate booleans, and all six byte-sorted policy lists through a domain-separated length-framed SHA-256 input hash.
The implemented durable result has a closed outcome vocabulary, a closed sorted reason-code vocabulary, canonical bounded reason JSON, and an exact prior version and input-hash compare-and-swap identity.
An exact persisted semantic result retains its original evaluation timestamp.
Sender policy parses one mailbox and derives its domain after the final `@`, urgent terms produce urgency only with an allow-domain signal, and blank canonical recipient entries never create direct-recipient evidence.
Literal term matching canonicalizes Unicode simple folds once per value and is limited to 512 searches over a folded subject of at most 16,384 bytes with each folded term limited to 512 bytes.
Each candidate-term and urgent-term list rejects Unicode case-fold-equivalent duplicates while input-hash list ordering remains byte-canonical.
After a reported commit success, evaluation returns a fresh exact durable read rather than the local proposal timestamp.

### 9.5 Review decisions

Hermes records a review result through MCP.

Valid outcomes are:

- `no_action`
- `keep_for_review`
- `task_proposed`
- `task_created`
- `deferred`

Store a bounded summary, reason, urgency, suggested project, suggested due date, source model metadata, reviewer identity, and timestamps.
Store the Vikunja task ID only after a separate Vikunja call succeeds.

Use an idempotency key derived from account ID, Gmail thread ID, review policy version, and task intent.
This key must prevent repeated Hermes runs from creating duplicate task decisions.

### 9.6 Audit events

Record security-relevant and state-changing events.

- Account authorization started, completed, refreshed, failed, paused, or revoked.
- Synchronization started, completed, retried, failed, or reconciled.
- Backfill range started, progressed, completed, paused, or failed.
- MCP review read and review decision write.
- Credential decryption failure.
- Authorization denial.
- Administrative command execution.

Audit records must not contain access tokens, refresh tokens, authorization codes, raw message bodies, or complete sensitive headers.

## 10. Gmail integration

### 10.1 OAuth

Use one Google OAuth client configuration for the service and authorize every account separately.
Store the Google subject ID for stable account identity.
Do not use Chrome profile numbers such as `/u/0` as identity.

Request the identity-only `openid` scope and the sole Gmail data scope `https://www.googleapis.com/auth/gmail.readonly` in the first release.
Do not request modification, compose, send, settings, contacts, Drive, or Calendar scopes.

Use authorization code flow with PKCE when supported by the selected Google application type and library path.
Use a cryptographically random state value with short expiration and one-time consumption.
Bind the state to the enrollment attempt.
Reject callbacks with a missing, expired, reused, or mismatched state.

The OAuth callback is an API endpoint required by the protocol.
It is not a web dashboard.
The operator command may print the authorization URL and wait for callback completion.

The implemented `account add` command is a one-shot flow whose callback path is exactly `/oauth/google/callback`.
It rejects every alias among the six selected Google, encryption, and database environment-variable names before resolving any value.
It uses independently generated 32-byte state and PKCE values, a ten-minute one-time attempt with an owned expiry wake-up, fixed Google endpoints, an owned redirect-rejecting HTTP client, 16,384-byte provider response limits, and one request per token, UserInfo, and Gmail profile operation.
The callback proves that a body of unknown declared length is empty before consuming the one-time attempt.
Successful token responses require a supported JSON or form encoding with no duplicate field or noncanonical sensitive JSON field, the exact two-scope set in either order, a bearer token, a refresh token, and a bounded positive expiry before OAuth decoding is accepted.
The long-running `serve` command remains health-only and does not register the callback.
Enrollment resolves the stable OpenID Connect subject before creating or adopting the canonical account and fetches Gmail `historyId` only after the account row is durable.
It initializes the cursor before encrypting and initializing the refresh token, never replaces an existing cursor or credential, and reports success only after fresh account, cursor, ciphertext, and authenticated-decryption checks.
Account-only and cursor-only states are restartable, credential-only state requires recovery, and the protocol does not claim three-record atomicity.
A concurrent same-subject initializer adopts any valid cursor that won durable initialization and never replays the losing cursor write in the same attempt.
Enrollment reads lifecycle state before staged persistence, activates only after fresh complete-state and decryption proof, treats active as complete, and rejects paused, reauthorization-required, or revoked accounts without changing cursor or credential state.

The implemented operator surface provides bounded canonical `account list`, idempotent `account pause`, complete-state `account resume`, and confirmed `account revoke` commands.
Revocation durably records revoked-pending intent, wins an exact status-and-version transition to revoked-attempting, and freshly reads the credential before decrypting or sending the refresh token.
Only a process with a proven attempting claim may contact Google, and credential persistence atomically rejects insertion or replacement after the lifecycle becomes revoked.
It sends one form-encoded POST to the fixed Google revocation endpoint with an owned redirect-rejecting transport, no retry, a 15-second deadline, and a 16,384-byte response limit.
Only HTTP 200 records confirmed, while every other proven provider outcome records manual-action-required, and both outcomes exact-compare-delete the encrypted local credential under an independent bounded cleanup context.
If credential inspection fails after the attempting claim, the operation remains attempting and returns recovery-required rather than creating a terminal row with unverified residual ciphertext.
A restart from revoked-pending may make one bounded provider attempt only after winning the attempting claim.
A restart from revoked-attempting never repeats the provider call and instead finalizes manual-action-required and exact-deletes any remaining ciphertext.
A finalized restart makes no provider request and only reconciles deletion.
Before any revocation mutation or provider work, the manager reserves three lifecycle increments for a non-revoked row, two for revoked-pending, or one for revoked-attempting.
Confirmed and manual-action-required rows require no further lifecycle increment and may reconcile residual ciphertext at the maximum version.

Encrypt refresh tokens before persistence with an application master key supplied through the runtime secret store.
Use standard-library AES-256-GCM with a 32-byte key, a fresh 12-byte nonce read completely from `crypto/rand.Reader`, and the 16-byte authentication tag.
Bind every refresh token to its exact ciphertext header, internal account ID, provider `gmail`, and purpose `oauth_refresh_token` through authenticated additional data.
The canonical keyring text starts with `igk1:` and contains one through eight unique key identifiers and unique raw 32-byte keys, with the first entry active for encryption and remaining decrypt-only identifiers sorted bytewise.
Each key uses unpadded raw URL-safe base64, and key identifiers match `[a-z][a-z0-9_-]{0,31}`.
The ciphertext text starts with `igc1.` and encodes the fixed magic, format version, algorithm identifier, key identifier, nonce, ciphertext, and tag as unpadded raw URL-safe base64.
Plaintext is limited to 1 through 4096 bytes, and ciphertext envelope text is limited to 55 through 5556 bytes.
Rotation decrypts with the referenced retained key and re-encrypts under the active key, while an envelope already using the active key remains byte-identical.
Retain every old decrypt key until all durable envelopes have been rotated and separately verified after restart.
Restore the keyring independently from the database before attempting credential recovery.
Never log tokens or authorization codes.

### 10.2 Initial account bootstrap

After authorization, request the account profile and record the provider subject and email address.
Fetch the current mailbox history ID before starting current-mail polling.

Create two distinct jobs.

- Current synchronization begins from the recorded current history ID.
- Historical backfill walks backward over the explicitly selected date window.

This separation prevents an old-mail backfill from delaying new mail.

### 10.3 Current-mail synchronization

Use Gmail history listing for incremental discovery.
Use bounded pages and explicit retry handling.
Fetch message metadata for newly added messages.
Apply the deterministic gate before fetching a larger body excerpt.

The implemented internal discovery prerequisite uses exact `users.history.list` requests with `historyTypes=messageAdded`, `maxResults` from 1 through 500, and a fixed partial-response selector.
It accepts no more than ten pages and stops before message retrieval when a continuation remains.
An exact history-endpoint 404 returns stale history without a cursor reset or full-sync request.
An exact message-endpoint 404 counts one vanished message, omits it from persistence, and may still advance the complete final cursor.

Each unique added message is read through one `format=FULL` request with a deterministic finite partial-response selector.
The selector includes only identifiers, labels, internal date, size estimate, selected top-level headers, MIME filenames, attachment identifiers, and at most 32 nested structural levels with an overflow sentinel.
It excludes snippets, raw MIME, message body data, body sizes, attachment bytes, classification values, and link targets.
The decoder accepts at most 1,000 MIME part nodes, counts non-root attachment metadata once per part, retains only the ten approved gate headers, and discards filenames and attachment identifiers after counting.
Malformed optional sender-controlled header syntax becomes an absent conservative signal before the record crosses `mail.Normalize`.

History and message GETs use one initial attempt and at most three retries only for transport failures, exact Gmail rate-limit reasons, HTTP 429, and HTTP 500, 502, 503, or 504.
Header acquisition, bounded response-body read, and response-body close failures are transport failures and consume the same explicit retry schedule while the caller remains active.
Oversized or malformed completed responses do not retry.
Retry bases are one, two, and four seconds plus zero through 250 milliseconds of cryptographic jitter, with canonical numeric `Retry-After` honored only from one through 30 seconds.
Each request has a 15-second deadline, preserves shorter caller cancellation, rejects redirects, and reads a bounded response before decoding.
Every OAuth, history, message, and Google error object uses byte-exact case-sensitive field allowlists at each nested level and rejects invalid raw UTF-8 or unpaired UTF-16 surrogate escapes.
Each explicit Gmail attempt uses a fresh nonpersistent HTTP/1 connection so the standard transport cannot add an uncounted retry beneath the one-two-four-second schedule.
The absolute invocation limit is one token request, 40 history attempts, and 20,000 message attempts.

This use case has no command, scheduler, service caller, HTTP route, MCP tool, capability activation, remote database path, or live credential path.
`gmail.read` and `gmail.current_sync` therefore remain not implemented and impossible to enable.

Polling may begin at a jittered five-minute interval per account.
Make the interval configurable within a safe minimum.
Do not add Gmail Pub/Sub until polling has a measured functional or quota problem.

Treat duplicate history events as normal.
Use database uniqueness and idempotent upserts.

### 10.4 Historical backfill

Backfill is metadata-first and resumable.
The operator must provide a start date or bounded Gmail query.
There is no unbounded `all mail forever` default.

Backfill stores page checkpoints and commits progress after each page.
Stopping and restarting the service must resume from the last committed checkpoint.
Current-mail synchronization always has priority over historical work.

Apply cheap exclusions before fetching body text.
Examples include spam, trash, known bulk categories, messages outside the selected range, duplicate messages, and configured sender rules.

Rate-limit per account and globally.
Respect `Retry-After` and exponential backoff with jitter for retryable responses.
Do not retry authorization failures indefinitely.

### 10.5 Message content

Do not store full raw MIME in the first release.
Fetch and store only a bounded, sanitized text excerpt for review candidates.

Prefer `text/plain` when available.
If only HTML is available, remove tags and unsafe invisible content with a small, tested sanitizer strategy.
Do not execute remote resources, scripts, CSS, forms, or tracking pixels.
Do not follow links while synchronizing.

Set explicit byte and character limits before persistence and before MCP return.
Record truncation explicitly.

The implemented inert candidate-content prerequisite accepts one typed account ID, one Gmail message ID, and the validated `gmail.body_excerpt_bytes` limit from 1,024 through 65,536 bytes.
It proves an active lifecycle, current canonical message, and current `review_candidate` or `urgent_review_candidate` gate decision before reading a credential or contacting Gmail.
After one accepted OAuth refresh it repeats the lifecycle, message, and gate reads and requires the exact prior lifecycle version, record identity, metadata hash, gate version, gate input hash, and candidate outcome.

The content request is one bodyless read-only `users.messages.get` with `format=FULL` and a finite selector containing only message identity, MIME type, `headers(name,value)`, filename, body size, body data, attachment ID, and 32 finite nested part levels.
Gmail field selection cannot filter the repeated headers array by name, so arbitrary header names and values may be present ephemerally within the 1 MiB total response cap.
The decoder consumes only Content-Type and Content-Disposition and discards every other header before the typed domain boundary, persistence, diagnostics, logs, or caller output.
The response is at most 1 MiB, the selected decoded part is at most 512 KiB, the tree is at most 1,000 nodes and 32 levels, and the request uses the accepted maximum of four explicit attempts with a 15-second deadline per attempt.
No attachment endpoint exists, and a filename-bearing, attachment-backed, or attachment-disposition node excludes its complete descendant subtree from selection.

Selection walks the complete bounded tree in provider order, chooses the first eligible inline `text/plain` part, and uses the first eligible inline `text/html` part only when no eligible plain part exists.
Selected data requires canonical unpadded Gmail base64url and exact declared-size agreement.
The closed charset set is UTF-8, US-ASCII, ISO-8859-1, and Windows-1252, with absent charset defaulting to US-ASCII.
Charset semantics are parsed only for an otherwise eligible inline text part, so bounded inert MIME parameters on excluded or non-text nodes do not make a valid visible sibling unavailable.
Content-Disposition is a single bounded closed decision per node: inline can remain eligible, while attachment or a disposition filename excludes the subtree and duplicate, unknown, conflicting, or malformed values fail closed.
Unknown, invalid, conflicting, or output-expanding charset data fails closed.

The repository-owned fail-closed HTML tokenizer emits text only, requires balanced unambiguous markup, permits self-closing syntax only for closed void elements, removes active and hidden subtrees, requires closed entity decoding before evaluating security-sensitive visibility attributes, handles exact hidden `!important` and numeric-zero forms, rejects ambiguous computed or obfuscated visibility values, and never emits attributes, URLs, images, CSS, forms, scripts, event handlers, or markup.
The shared canonicalizer normalizes line endings, replaces disallowed controls, removes reviewed bidirectional and unsafe invisible formatting characters, trims line ends, collapses excessive blank lines, and truncates only at a UTF-8 boundary.
It canonicalizes the truncated prefix again so a newly exposed boundary byte cannot violate durable form while retaining the original `truncated=true` decision.
Construction and durable decoding apply the same canonical-excerpt predicate, so noncanonical content cannot enter through a typed caller or malformed durable row.
Malformed HTML and an empty canonical result are unavailable and never fall back to raw HTML.

Candidate-content version 1 stores only extractor version, canonical record ID, source metadata hash, gate version and input hash, source kind, excerpt, excerpt byte count, configured limit, truncation flag, domain-separated content hash, and first fetched timestamp.
The application boundary always adds `content_trust: untrusted_email` semantics.
Migration `0007_candidate_content.sql` stores one strict `WITHOUT ROWID` row per canonical record under a restrictive foreign key and exact compare-and-swap replacement identity.
The fake and exact-driver implementations preserve the first fetched timestamp for an exact semantic retry and use one mutation attempt plus separate physical visibility proof for uncertain outcomes.

The extractor has no command, scheduler, service caller, HTTP route, MCP tool, health or capability registration, remote Turso path, or live credential path.
The validated `retention.excerpt_days` value is not an active deletion mechanism in this slice.
Future MCP candidate and thread tools must consume this typed bounded boundary and must not duplicate Gmail, MIME, charset, HTML, persistence, or trust policy.

## 11. Deterministic gate

The gate exists to reduce model exposure and cost.
It must not call a model.
It must be a pure, versioned function over normalized metadata and a bounded optional excerpt.

Initial signals may include the following data.

- Gmail system labels and categories.
- Sender allowlists and denylists.
- Direct recipient versus mailing-list recipient.
- Presence of `List-Unsubscribe` or list headers.
- Automated sender and precedence headers.
- Subject keywords configured by the owner.
- Whether the sender has an existing open review or task history.
- Whether the message is part of a previously reviewed thread.
- Age and account-specific rules.

Do not implement machine learning in the gate.
Do not infer urgency solely from words such as `urgent` in untrusted email.

Gate rules must produce stable reason codes.
Examples include `bulk_category`, `known_automated_sender`, `direct_human_sender`, `existing_review_thread`, and `owner_keyword_match`.

The first default policy should be conservative.
It should pass ambiguous direct human mail to review and suppress obvious bulk mail.
The owner must be able to inspect why a message was suppressed through MCP or an operator command.

## 12. MCP surface

Expose streamable HTTP MCP on a private route.
Require an independent high-entropy bearer token for Hermes.
Do not reuse the Gmail OAuth token, Turso token, Tailscale auth key, or Vikunja token.

The first tool set is intentionally small.

### 12.1 Read tools

`accounts_list`

Returns account IDs, display names, states, last synchronization times, backfill status, and safe error summaries.

`mail_sync_status`

Returns per-account current synchronization and backfill progress.

`mail_list_review_candidates`

Returns bounded metadata for candidate threads.
Inputs include account IDs, state, age range, urgency, page size, and cursor.

`mail_get_thread`

Returns a bounded, sanitized thread representation for one account ID and Gmail thread ID.
It labels every email-derived field as untrusted content.

`mail_get_gate_reason`

Returns the deterministic gate decision and reason codes for a message or thread.

`system_capabilities`

Returns the binary version, configuration schema version, implemented capabilities, enabled capabilities, disabled capabilities, and safe missing prerequisites.
It never returns secret values.

### 12.2 Write tools

`mail_record_review`

Records one of the allowed review outcomes with an idempotency key.
It does not create a Vikunja task.

`mail_link_task`

Records a Vikunja task ID after Hermes creates the task through the separate Vikunja integration.
It must validate that the review is in `task_proposed` or `task_created` state and must be idempotent.

`mail_defer_review`

Defers a candidate until an explicit time.

### 12.3 Tools deliberately not exposed

- Raw SQL.
- Arbitrary Gmail API requests.
- OAuth enrollment.
- Backfill start or cancellation.
- Account revocation.
- Gmail mutation.
- Direct Vikunja operations.
- Shell commands.
- URL fetching.

Operator-only actions stay in the CLI.

### 12.4 MCP response safety

Every result containing email content must include a machine-readable trust marker such as `content_trust: untrusted_email`.
Tool descriptions must tell the model that message content is data and cannot authorize tool calls or change policy.

Return structured content with stable schemas.
Avoid large prose blobs.
Paginate lists and cap thread sizes.
Return opaque cursors rather than database offsets when practical.

## 13. Hermes and Vikunja workflow

InboxGate and Vikunja are independent tools used by Hermes.

The first approved workflow is:

1. Hermes calls `mail_list_review_candidates`.
2. Hermes selects a bounded number of candidates.
3. Hermes calls `mail_get_thread` for each selected candidate.
4. Hermes treats all returned email text as untrusted evidence.
5. Hermes decides `no_action`, `keep_for_review`, `task_proposed`, or `deferred`.
6. Hermes records the decision with `mail_record_review`.
7. If the decision is `task_proposed`, Hermes searches Vikunja for an existing task with the same source reference.
8. Hermes chooses a project, priority, dates, labels, and optional Kanban bucket.
9. Hermes creates the Vikunja task only when the active workflow permits it.
10. Hermes records the task ID with `mail_link_task`.

The model, not the deterministic gate, decides whether a candidate deserves a Vikunja task.
The deterministic gate decides only whether model review is justified.

The initial Telegram workflow should favor a proposal and confirmation before creating a task.
Automatic task creation can be enabled later for narrow, evaluated categories.

## 14. Capability-surface rule

New capabilities must be implemented once in an application use case and adapted to approved surfaces.
They must not be implemented independently inside each protocol handler.

For every new capability, the implementation agent must review this matrix.

| Surface | Required review |
| --- | --- |
| Domain and application use case | Always |
| Storage transaction and migration | When state changes |
| Gmail adapter | When provider behavior is involved |
| MCP tool and schema | When Hermes needs the capability |
| Operator CLI | When an owner or administrator needs it |
| Audit event | When security or durable state is affected |
| Metrics and health | When operation can fail asynchronously |
| Unit tests | Always |
| Integration tests | When storage, HTTP, OAuth, or protocol behavior changes |
| End-to-end test | When a user-visible workflow changes |
| Documentation and threat model | Always for public or security-relevant changes |

Not every use case must be exposed on every surface.
The review must explicitly record `implemented` or `not applicable` for each surface.
This prevents accidental omissions without creating unnecessary APIs.

The initial registry slice has these surface decisions.

| Surface | Decision |
| --- | --- |
| Domain and application | One typed read-only registry with fail-closed derived enablement |
| Configuration | Five false-by-default gates and strict rejection of unknown or unimplemented enablement |
| Storage and migration | Not applicable |
| Gmail and OAuth | Not applicable |
| MCP | Not implemented in this slice |
| Operator CLI | Local deterministic JSON inspection only |
| Audit, metrics, and health | Not applicable |
| Tests | Unit, parser, renderer, and real-process coverage |
| Documentation and threat model | Required and updated |

## 15. Turso persistence

Turso Cloud is the canonical operational database for the first release because it keeps synchronization and review state outside the Hetzner VM.
Gmail remains the source of truth for raw email.

Create a new Turso Database rather than a legacy libSQL database.
The operator should use the Turso database-engine creation option documented at implementation time and record the resulting engine type in the deployment runbook.

[ADR 0004](adr/0004-turso-serverless-adapter.md) accepts the current official remote `tursogo-serverless` driver behind the narrow repository-owned storage adapter.
The adapter provides open, bounded ping, idempotent close, narrow embedded migration, typed minimum account-cursor operations, typed ciphertext-only provider-credential compare-and-swap operations, bounded typed account-lifecycle operations, a typed atomic current-discovery aggregate, typed gate-decision compare-and-swap, and typed candidate-content current read and compare-and-swap.
Migration, account-cursor, ciphertext-credential, lifecycle, current-discovery, gate-decision, and candidate-content execution are restricted to credential-free literal-loopback endpoints.
The one-shot `account add` command connects configuration-selected runtime values, OAuth enrollment, and typed persistence operations.
The `account list`, `account pause`, `account resume`, and confirmed `account revoke` commands connect only the minimum selected database and encryption values required for their operation.
Live Turso credentials and remote database activation remain prohibited.
The health-only service, capability inspection, configuration inspection, and doctor do not activate this persistence boundary.

The owner accepts the unresolved `base_url` authority, raw remote diagnostic, transaction completion, close context, terminal acknowledgement, private HTTP client and redirect policy, and successful-response bound risks recorded in the [known-risk register](known-risks.md).
That acceptance permits focused storage implementation to continue but does not describe the risks as fixed.
Every later storage issue must identify which accepted risks it reaches and add containment or obtain a new decision before broadening the boundary.

Do not use local Turso Sync or an embedded replica in the first release.
The service already runs continuously in the cloud, and remote access keeps the process and container simpler.
Reconsider local sync only if measured availability or latency requires it.

Use one logical database for the single owner.
Do not add tenant partitioning until a second human user is approved.

Use handwritten SQL and explicit transactions.
Use foreign keys where supported.
Create unique constraints for all provider identifiers and idempotency keys.

Set conservative connection limits from the validated configuration.
The accepted adapter requires HTTPS with standard TLS certificate and hostname verification and rejects cleartext remote URLs before driver construction.
Plain HTTP may be used only with a literal loopback endpoint in credential-free tests, with no bearer token or production-derived secret attached.
The current adapter maps ping, migration, account, cursor, credential, lifecycle, current-discovery, gate-decision, candidate-content, and returned close failures to fixed diagnostics and bounds ping and context-aware storage statements with owned deadlines.
Authority handling, redirect behavior, successful-response body, cursor-line, row and value limits, and caller-controlled commit, rollback and close cancellation remain accepted unresolved risks.
The credential-free migration contract verifies parameterized ledger inspection, an exact bounded atomic pipeline sequence, `BEGIN IMMEDIATE` locking, transaction-local validation of the exact row total and every expected pair with null rejection, internally rendered numeric and lowercase-hex catalog metadata, exact checksum drift rejection, bounded rollback attempts with unknown outcomes, no same-invocation replay, and fresh-run reconciliation after an uncertain sequence.
Every purportedly successful migration commit requires a same-session savepoint sequence that acquires main-database writer serialization through a bounded ledger self-assignment, revalidates the same exact null-rejecting ledger prefix, and refuses to regress a concurrently advanced code-owned `PRAGMA user_version` marker, followed by separate-connection visibility of both the exact ledger and marker while the apply connection remains reserved.
An apply connection whose autocommit state cannot be proven is discarded from the pool after cleanup is attempted.
It does not prove remote engine behavior or close the accepted driver risks before production data is stored.
Do not assume every SQLite pragma or extension is available remotely.
Do not automatically replay a statement after a transport failure because its server-side outcome may be uncertain.

Migrations are append-only numbered SQL files.
The migration runner records the migration number and checksum.
It must refuse to run if an already applied migration has a different checksum.
The embedded catalog starts with immutable `0001_migration_ledger.sql`, appends minimum account-cursor schema in `0002_accounts_and_sync_cursors.sql`, appends ciphertext-only provider credentials in `0003_provider_credentials.sql`, appends strict account lifecycle state in `0004_account_lifecycle.sql`, appends atomic current-discovery staging in `0005_current_discovery_atomic_commit.sql`, appends strict gate decisions in `0006_gate_decisions.sql`, appends strict bounded candidate content in `0007_candidate_content.sql`, and is limited to 256 migrations, 256 KiB per file, and 4 MiB total.
The runner inspects current state outside a transaction, sends pending work as one bounded no-argument `BEGIN IMMEDIATE` through `COMMIT` pipeline sequence, verifies the exact prefix row total and every expected pair under the writer lock while rejecting nulls, proves terminal session state without marker regression through the code-owned `user_version` marker and a separate physical connection, and applies at most one pending migration per transaction.
The sequence accepts no caller data and renders only a bounded code-derived migration number and validated lowercase-hex checksum as SQL literals because the driver's sequence request cannot carry arguments.
The prefix guard renders only bounded catalog numbers and validated lowercase-hex checksums, and none of those literals come from users, providers, configuration, or database rows.
A durable ledger with a missing marker is reconciled by marker repair without schema replay, while a marker ahead of the ledger is drift.
Credentialed and non-loopback migration execution is rejected before any migration request.

The storage contract accepts a pre-generated validated account ID and an opaque validated provider subject while fixing the provider to `gmail` internally.
The durable schema measures these text forms as bytes and explicitly rejects embedded NUL bytes rather than relying on SQLite text length or glob behavior.
Account creation is idempotent by binary `(provider, provider_subject)` uniqueness, never updates identity, and attempts at most one fixed parameterized insertion per invocation.
The cursor initialization contract accepts only an account ID, an absent expected history ID, and a required initial history ID.
`CommitSynchronization` uses one fixed parameterized implicit-transaction statement that explicitly checks account existence, initializes only from an absent cursor, rejects every present cursor, never advances an existing cursor, and performs no delete or reset.
Account and cursor lookups require exactly one semantic sentinel row, validate all decoded columns and values, and reject a clean end of stream as inspection failure rather than absence.
Every attempted product-state mutation keeps its connection reserved until a separate physical connection observes the exact durable account identity or next cursor.
Successful-looking responses without visible state and uncertain failures without visible state return a bounded unknown outcome, discard the mutation session, and never trigger same-invocation replay.
A fresh explicit invocation may reconcile a state that became durable after an uncertain response.
These operations use only fixed parameterized SQL and bounded validated values and expose no raw SQL, generic executor, transaction callback, or driver type.

Provider credentials use a separate typed compare-and-swap operation whose inputs are an account ID, an optional exact expected ciphertext envelope, and a required next ciphertext envelope.
Initialization succeeds only from absence, replacement succeeds only from the exact expected envelope, and an already durable next envelope is idempotent success.
The one fixed parameterized mutation derives the stored key identifier only from the validated next envelope, never accepts plaintext, and never exposes a delete or blind overwrite.
Its source predicate permits initialization only with a nil expected envelope and permits replacement only when the same account has the exact non-nil expected envelope, while the conflict update repeats that exact expected-envelope guard.
The mutation connection remains reserved until a separate physical connection observes the exact durable next envelope.
Only an exact one-row affected acknowledgement plus exact separate visibility allows that connection to return to the pool, while incomplete or zero-row acknowledgements force discard even when visibility proves the requested ciphertext durable.
Unknown outcomes discard the mutation session and never replay in the same invocation.
The no-SQL fake implements the same typed behavior for credential-free higher-layer tests.

Lifecycle persistence exposes only a bounded ordered account summary, one typed state-status-version compare-and-swap, one typed lifecycle lookup, and one revoked-only exact ciphertext compare-and-delete.
Lifecycle and credential-deletion mutations use fixed parameterized SQL, one mutation attempt, a reserved apply connection, separate physical visibility, session discard on uncertainty, and no same-invocation replay.
Credential initialization and replacement use a fixed atomic lifecycle predicate that rejects every revoked account.
Account listing reads at most 101 rows, rejects more than 100, and fails closed if an account lacks its required lifecycle row or if any returned value is malformed.
The exact-driver fixtures exercise dropped and incomplete responses before and after durability, fresh reconciliation, redirect and authority behavior, oversized values, fixed diagnostics, and session discard while keeping `TURSO-001` through `TURSO-005` open.
The credential-free literal-loopback fixture asserts exact migration bytes and driver protocol behavior but does not execute SQLite, so dependency-free catalog tests additionally assert the exact lifecycle constraint shape.

Current discovery persists only normalized metadata version 1 and excludes bodies, snippets, raw MIME, attachment bytes, link targets, OAuth data, raw provider JSON, and arbitrary headers.
The record ID is a full domain-separated SHA-256 digest of the validated account ID and Gmail message ID.
The attempt ID and manifest hash are separate domain-separated full SHA-256 digests of exact length-prefixed canonical inputs.
The durable `manifest_witness` is lowercase hexadecimal of the complete manifest-hash preimage and binds every ordinal-ordered staged field through schema-verifiable `row_witness` values.
One account has at most one open or sealed attempt, and each staging request uses 64 fixed slots and exactly 514 positional parameters.
Unused final slots use a zero presence flag and null non-control values.
The fixed staging insert reconstructs `row_witness` from every live field, and schema triggers reject every staging update.
Seal and finalization reconstruct each row witness from the live columns and reconstruct the complete ordinal-ordered manifest witness before canonical or cursor mutation.
The adapter decodes and re-encodes canonical metadata, verifies its SHA-256 metadata hash, and verifies the derived record ID before it requests finalization.
The maximum serialized stage request is 40 MiB.
The write-only finalization view requires a sealed complete witness-bound manifest, active lifecycle, exact cursor, stable thread identity, and collision-free canonical keys.
The trigger does not recompute any SHA-256-derived identity.
Its trigger promotes canonical messages, updates only bounded mutable metadata, advances the exact cursor, and removes only that attempt's staging rows as one database statement.
Open and sealed staging never changes canonical messages or the cursor before successful finalization.
Pause and reauthorization-required retain staging and block finalization, while transition to revoked removes only noncanonical attempt state and preserves canonical messages.
Every current-discovery mutation is attempted at most once per invocation, keeps its connection reserved during separate-connection proof, discards an unproven session, and requires a fresh explicit invocation for reconciliation.
The exact-driver loopback model verifies fixed SQL, 514 arguments, chunk bounds, uncertainty boundaries, separate visibility, concurrency outcomes, cancellation, fixed diagnostics, and no same-invocation replay.
It does not execute a database engine and therefore does not prove Turso Database support for 514 parameters, strict tables, triggers, constraint rollback, writer serialization, or concurrent finalization.
The manifest witness is bounded at 33,554,510 bytes, while all row witnesses together can add another 33,554,432 bytes of hexadecimal text in addition to the live staging fields and database overhead.
This deliberate integrity control amplifies bounded storage and successful-response size, so runtime activation requires later pinned engine evidence or owner-approved sanitized evidence for the exact parameter limit, ordered witness reconstruction, allocation behavior, trigger rollback, writer serialization, and concurrency properties without sharing an endpoint, token, database identity, account identity, message metadata, cursor, or provider response.
Arbitrary raw-SQL authority could create a self-consistent attempt that the trigger cannot distinguish from application-created state, but InboxGate exposes no raw-SQL surface.

Test restoration by creating a fresh service instance from only the repository, runtime secrets, and Turso database.
Do not treat Turso as the only place OAuth encryption keys exist.
Back up the application master key separately in the owner's secret manager.

Turso protects the operational database from loss of the Hetzner VM, but it is not the complete backup strategy.
Turso currently documents automatic point-in-time recovery at every commit, with a 24-hour restore window on the free plan and longer windows on paid plans.
A restore creates a new database and requires a new connection URL or token.
The deployment runbook must include a quarterly restore drill and a documented procedure for updating the service secret after recovery.

Before relying on the free plan, confirm the current quotas, retention, database engine, region, and recovery terms in the owner's Turso account.
Provider tokens and the application encryption key need an independent recoverable secret backup because a database restore cannot reconstruct the encryption key.

## 16. HTTP and runtime security

Bind the service to the private deployment network.
Expose it to devices through Tailscale or the existing private reverse-proxy path.
Do not expose MCP, OAuth administration, health details, or operator routes to the public internet.

Use separate authentication for MCP and operator actions.
The first release does not need a browser administration session.

Set explicit HTTP server timeouts, header limits, request-body limits, and graceful shutdown.
Reject unexpected content types.
Use constant-time comparison for fixed bearer secrets where applicable.
Do not put secrets in URLs.

The initial health-only runtime exposes exactly `GET` and `HEAD` on `/health/live` and `/health/ready`.
Percent-encoded alternate path spellings are unmatched even when URL decoding would produce a health path.
It uses fixed bounded JSON responses, a compiled 16 KiB header limit, a compiled limit of 128 concurrently accepted connections, the configured timeouts and request-body limit, and no provider, storage, OAuth, MCP, scheduler, or mutation route.
The listener acquires an admission permit before accepting a connection into application work and reuses that permit only after the accepted connection closes.
Readiness reports only an active serving lifecycle after strict configuration validation, logger and server construction, and listener establishment.
It becomes false before shutdown draining begins.
The unauthenticated health routes disclose no configuration, address, host, account, connectivity, provider, secret, migration, scheduler, or process details and must remain on an approved private interface or private reverse-proxy path.
The first termination signal permits active requests to drain for up to a compiled 10 seconds without allowing another signal to extend the deadline.

Apply least privilege to the container.
Run as a non-root user.
Use a read-only root filesystem when the runtime and certificate handling permit it.
Write only to an explicit temporary directory.
Drop Linux capabilities.
Do not mount the Docker socket.

## 17. Prompt-injection boundary

Email is hostile input.
An email may contain text that instructs an agent to reveal secrets, call tools, modify tasks, visit a URL, or ignore policy.

InboxGate must never interpret message text as instructions.
It only stores, filters, and returns bounded data.

Hermes must be taught that email content has lower authority than system, owner, skill, and tool policy.
An email cannot authorize a Gmail mutation, Vikunja write, shell command, credential disclosure, network request, or policy change.

Task proposals should include source facts and the account-aware Gmail link, but should not copy long email bodies into Vikunja.
Secrets or sensitive personal data detected in a message should be omitted from summaries when not needed for the task.

## 18. Observability

Use `log/slog` with JSON output in production.
Include request ID, account ID, operation, outcome, duration, and retry class only where the corresponding bounded operation requires them.
Never include tokens or complete message bodies.

Expose a minimal liveness endpoint that reports only process health.
Expose an authenticated readiness or diagnostics endpoint for database access, migration status, scheduler state, and Gmail account summaries.
The initial unauthenticated readiness endpoint reports only whether the process is actively serving and not shutting down.
Detailed local preflight remains in `doctor` until a separately authenticated diagnostics surface is approved.

Start with counters and durations derivable from structured logs.
Do not add a metrics dependency until a concrete monitoring consumer exists.

## 19. Test strategy

### 19.1 Test doubles

Use `httptest.Server` for OAuth token, Google identity, and Gmail API behavior.
Use synthetic fixtures for messages and history pages.
The accepted Turso adapter contract uses a no-SQL fake replacement and a credential-free literal-loopback SQL over HTTP server.
It verifies initial endpoint policy, URL and token separation, bounded operation cancellation, fixed diagnostics, idempotent close, exact fixed parameterized account-cursor and ciphertext-credential statements, durable uniqueness, typed compare-and-swap, separate physical visibility, uncertain outcomes, session discard, no replay, and fresh reconciliation.
The literal-loopback server exercises the exact pinned HTTP driver but models SQL durability and does not execute SQLite.
It does not prove Turso Cloud availability, quota, latency, recovery, engine-specific behavior, same-authority handling after `base_url`, redirect rejection, successful-response limits, or bounded transaction and stream close.
Those gaps remain in the [known-risk register](known-risks.md) and must be exercised when a later issue reaches the affected behavior.
Do not mock SQL with a third-party SQL-mocking library.

Create a small fake clock only when time-dependent tests require it.
Create deterministic random sources only where OAuth state or jitter tests require them.

### 19.2 Required unit tests

- Gate rules and stable reason codes.
- Gmail response decoding.
- MIME-part selection and sanitization bounds.
- Account-aware message and thread keys.
- Cursor commit rules.
- Retry classification and backoff bounds.
- OAuth state lifecycle.
- Credential encryption, decryption, versioning, and tamper rejection.
- Review state transitions.
- Review and task-link idempotency.
- MCP input validation and output bounds.
- YAML unknown-key, duplicate-key, alias, tag, multi-document, size, and depth rejection.
- Configuration defaults, bounds, capability validation, and secret redaction.

### 19.3 Required integration tests

- SQL migrations from an empty database.
- Migration checksum mismatch rejection.
- Account creation and encrypted token persistence.
- Gmail history page commit with cursor transactionality.
- Duplicate message ingestion.
- Stale history cursor reconciliation state.
- Backfill checkpoint resume.
- MCP authentication.
- MCP tools/list and tools/call contracts.
- Graceful shutdown while synchronization is active.
- Accepted database driver authority, error, cancellation, transaction, rollback, constraint, and concurrent-access behavior.
- Configuration validation without external network access.

### 19.4 Required end-to-end tests

The minimum end-to-end test starts a fake Google OAuth and Gmail HTTP service, an isolated database, and InboxGate.
It authorizes a synthetic account, discovers current messages, suppresses bulk mail, exposes one review candidate through MCP, records a review, and confirms that no Gmail mutation or Vikunja call occurred.

A second end-to-end test stops a historical backfill after a committed page, restarts InboxGate, and proves that the backfill resumes without duplicate records.

### 19.5 Quality gates

The default CI command must run formatting checks, `go vet`, unit tests, integration tests that require no external secret, race tests for concurrent synchronization code, and a build.

All tests must pass from a clean checkout without a Google, Turso, Gmail, Hermes, Vikunja, or Tailscale credential.
Live-provider tests must be opt-in and must never run in pull requests from forks with secrets.

## 20. Incremental implementation plan

Each phase begins with a failing acceptance test and ends with a small working vertical slice.

### Phase 0: Repository skeleton

Deliver only the Go module, license placeholder, README, security policy, contribution guide, Makefile or documented Go commands, CI, and one failing smoke test for the future binary.
Then implement the smallest binary that satisfies the smoke test.

Do not add runtime dependencies in this phase.

### Phase 1: Configuration and process health

Test and implement strict YAML parsing, compiled defaults, validation, redacted effective output, the capability registry, explicit environment validation, `serve`, liveness, readiness, structured logging, graceful shutdown, and `doctor`.
The YAML package is the only runtime dependency approved in this phase.

### Phase 2: Storage and migrations

[ADR 0004](adr/0004-turso-serverless-adapter.md) resolves the driver-selection gate with an inert repository-owned adapter and explicitly accepted unresolved risks.
[ADR 0005](adr/0005-append-only-migration-protocol.md) implements the credential-free append-only migration runner and checksum protection.
[ADR 0006](adr/0006-minimum-account-cursor-persistence.md) implements minimum Gmail account identity and synchronization-cursor persistence with synthetic fixtures only.
[ADR 0007](adr/0007-versioned-provider-credential-encryption.md) implements versioned authenticated encryption and ciphertext-only typed credential persistence with synthetic fixtures only.
[ADR 0008](adr/0008-google-oauth2-client.md) implements one-account Gmail OAuth enrollment against fake OAuth and Gmail servers.
[ADR 0009](adr/0009-account-lifecycle-and-revocation.md) implements durable account lifecycle state and credential-free synthetic revocation.
[ADR 0010](adr/0010-atomic-current-discovery-staging.md) implements canonical metadata persistence and transactional cursor movement through bounded staging.
[ADR 0011](adr/0011-bounded-gmail-current-discovery.md) implements one inert bounded current-discovery invocation against synthetic providers and fake or credential-free literal-loopback storage.
[ADR 0012](adr/0012-deterministic-persisted-gate.md) implements one inert deterministic classifier and typed persisted decision boundary with synthetic fixtures only.
Do not activate live credentials or production database writes without a separately approved issue and explicit owner approval.
Do not add email or review tables until their vertical slices require them.

### Phase 3: OAuth enrollment

One Gmail account enrollment, OAuth state protection, identity lookup, encrypted refresh-token persistence, bounded account listing, durable pause and resume, typed reauthorization state, and staged revocation are implemented with synthetic fixtures.
The enrollment and lifecycle commands do not call Gmail message endpoints.

### Phase 4: One current-mail discovery slice

Current history discovery for one account, normalized metadata persistence, duplicate handling, bounded retry behavior, and transactional cursor movement are implemented as an inert internal prerequisite.
Durable stale-history status and a runtime caller remain to be implemented.
Do not implement historical backfill yet.

### Phase 5: Deterministic gate

The smallest useful gate for obvious bulk mail and ambiguous direct mail is implemented as an inert internal prerequisite.
Decisions and stable reason codes persist through fake or credential-free literal-loopback storage.
Do not add model calls.

### Phase 6: Read-only MCP

Test and implement authenticated MCP transport, account listing, synchronization status, candidate listing, thread retrieval, and gate-reason inspection.
Integrate Hermes only after protocol tests pass.

### Phase 7: Review state

Test and implement review recording, deferral, task-link recording, and idempotency.
Do not call Vikunja from InboxGate.

### Phase 8: Historical backfill

Test and implement bounded Gmail query backfill, checkpoints, resume, current-mail priority, rate limiting, and progress reporting.

### Phase 9: Production hardening

Complete container hardening, private networking, secret injection, restore drill, resource limits, operational runbook, and production acceptance tests.

### Phase 10: Evaluation before expansion

Measure candidate rate, suppressed-message samples, false-negative reports, review latency, duplicate rate, database growth, Gmail quota usage, and model token use in Hermes.

Only then decide whether to add local Ollama analysis, Gmail Pub/Sub, Zoho, a dashboard, or direct A2A adapter.

## 21. Agent execution rules

The implementation agent must follow these rules.

1. Read this entire specification before modifying files.
2. Show the proposed repository tree and Phase 0 acceptance test before creating production code.
3. Work on one phase at a time.
4. Begin every behavior with a failing test and show the failure.
5. Implement the minimum code required to make that test pass.
6. Refactor only while tests remain green.
7. Do not add a dependency without the required decision record.
8. Do not invent provider fields or endpoints.
9. Use the Gmail REST documentation and recorded test fixtures as the authority.
10. Never use live production credentials in tests.
11. Never broaden OAuth scopes to solve an unrelated problem.
12. Never expose a raw Gmail, SQL, shell, or HTTP passthrough tool.
13. Stop and request owner approval before deployment, OAuth consent, secret creation, production database migration, or public repository publication.
14. Keep commits small and phase-oriented.
15. Do not add an AI assistant as a commit co-author.
16. Update the capability-surface matrix whenever a capability is added.
17. End each phase with test evidence, changed-file inventory, threat-model impact, dependency diff, and remaining scope.
18. Keep `config.example.yaml`, configuration validation tests, capability output, and operator documentation synchronized with every configurable capability.

## 22. Definition of done for the first release

The first release is complete when all of the following statements are true.

- At least two synthetic accounts and one owner-approved real test account can be enrolled independently.
- Account identity does not depend on Gmail browser profile numbers.
- Current mail is discovered incrementally and idempotently.
- A stale Gmail history cursor is handled without silent data loss or an unbounded restart.
- A bounded historical backfill resumes after process restart.
- Obvious bulk mail is filtered without a model.
- Hermes can list and inspect bounded review candidates through authenticated MCP.
- Hermes can record a review and link a separately created Vikunja task without duplication.
- InboxGate cannot send, delete, archive, label, or mark email read.
- Email content is returned as explicitly untrusted data.
- OAuth refresh tokens are encrypted at rest and absent from logs.
- The service can be rebuilt on a fresh VM and recover its operational state from Turso plus separately restored secrets.
- All CI quality gates pass from a clean checkout without production secrets.
- No web UI, Zoho adapter, local model worker, direct Vikunja client, or direct A2A server has been added.
- The example configuration validates, contains no secret values, and documents every supported setting.
- Unknown configuration and attempts to enable unimplemented capabilities fail closed.
- The production database uses the documented Turso Database engine and the exact driver accepted by ADR 0004 or a later superseding decision.
- A Turso point-in-time recovery drill has been documented and successfully tested before production sign-off.

## 23. Future candidates that are not approved yet

The following items require separate evidence and approval.

- Local Ollama classification worker.
- Zoho Mail adapter.
- Gmail Pub/Sub push delivery.
- Attachment extraction.
- Draft generation.
- Gmail mutations.
- Web dashboard.
- Search index beyond Turso queries.
- Multi-user tenancy.
- Direct A2A adapter.
- Custom analytics dashboard.

The second provider will justify extracting a provider interface only after Gmail behavior is stable and the differences are understood.
The first local model will justify a job lease protocol only after a measured review bottleneck exists.

## 24. External references for the implementation agent

- [Gmail API overview](https://developers.google.com/workspace/gmail/api/guides)
- [Gmail API authorization scopes](https://developers.google.com/workspace/gmail/api/auth/scopes)
- [Gmail history synchronization](https://developers.google.com/workspace/gmail/api/guides/sync)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/latest)
- [Official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk)
- [Turso documentation](https://docs.turso.tech/)
- [Turso Go quickstart](https://docs.turso.tech/sdk/go/quickstart)
- [Turso Go reference](https://docs.turso.tech/sdk/go/reference)
- [Turso durability guarantees](https://docs.turso.tech/cloud/durability)
- [Turso point-in-time recovery](https://docs.turso.tech/features/point-in-time-recovery)
- [Maintained Go YAML implementation](https://github.com/yaml/go-yaml)
- [Vikunja API v2](https://vikunja.io/docs/api-v2/)
- Vikunja and Hermes integration details are maintained outside this public repository.
