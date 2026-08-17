# ADR 0006: Minimum account and synchronization-cursor persistence

Status: accepted for credential-free synthetic execution

Date: 2026-08-17

## Context

InboxGate needs a durable identity for each independently authorized Gmail account and a durable Gmail history cursor before OAuth enrollment or message synchronization can be implemented.
The slice must remain testable without Google or Turso credentials and must not activate persistence from the runtime.
The selected remote driver remains pinned under ADR 0004 with unresolved risks `TURSO-001` through `TURSO-005`.
ADR 0005 supplies the append-only migration protocol and requires every later schema change to append a canonical reviewed file.

The driver can return ambiguous or incomplete acknowledgements and buffers successful protocol responses before repository validation.
The repository therefore cannot treat an affected-row count or a successful-looking response as durable proof of a product-state mutation.
The storage boundary must also prevent driver, `database/sql`, SQL text, and transaction mechanics from spreading into application code.

## Decision

Append `0002_accounts_and_sync_cursors.sql` without changing any byte of migration `0001`.
The migration creates only `inboxgate_accounts` and `inboxgate_synchronization_cursors`.

An account row contains an opaque internal account ID, provider fixed to `gmail`, and opaque provider subject.
The account ID is exactly 32 lowercase hexadecimal ASCII characters.
The provider subject is case-sensitive visible ASCII from 1 through 255 bytes with binary collation.
The schema measures stored text as bytes and rejects embedded NUL bytes explicitly because SQLite text functions and glob matching can stop at NUL.
The database enforces unique `(provider, provider_subject)` identity and never uses the provider subject as the primary key.

A synchronization-cursor row contains only an account ID and one canonical positive uint64 Gmail history ID encoded as decimal text.
The database rejects zero, leading zeroes, signs, whitespace, non-digits, and values above `18446744073709551615`.
An absent cursor row means that synchronization has not been initialized.
The foreign key restricts deletion, and the mutation statement separately verifies account existence instead of relying only on connection-local foreign-key settings.

The repository-owned `storage.Handle` exposes only typed `EnsureAccount`, `GetSynchronizationCursor`, and `CommitSynchronization` operations in addition to existing lifecycle and migration methods.
It exposes no database handle, driver type, raw SQL, generic executor, transaction callback, or caller-selected provider.
All input and decoded database values pass the same repository validation.

`EnsureAccount` performs a fixed parameterized sentinel-row preflight and returns the canonical account for an existing provider subject.
It returns a bounded conflict if the proposed account ID is already bound to another subject or the proposed ID and subject resolve to different rows.
If neither identity exists, it attempts one fixed parameterized insert with conflict suppression and never updates identity.

`CommitSynchronization` performs a fixed parameterized sentinel-row preflight.
It accepts initialization only when the expected cursor is absent, accepts advancement only from the exact expected cursor to a strictly greater next cursor, treats the already durable next cursor as idempotent success, rejects stale expectations, and rejects regression.
The only cursor mutation is one fixed parameterized SQLite `INSERT ... ON CONFLICT DO UPDATE` statement executed through the driver's implicit transaction.
No delete, reset, or lower overwrite exists.

Each mutation invocation attempts its statement at most once.
The mutation connection remains reserved while a separate physical connection verifies the exact durable account identity or requested next cursor.
Exact separate visibility is the success authority even when the mutation acknowledgement is malformed or lost.
Absent, expected, or different visible state cannot be reported as success.
An unproven mutation session is discarded, the operation returns a bounded unknown-outcome category, and no same-invocation replay occurs.
A later explicit invocation may reconcile committed state through preflight or attempt previously absent state once.

Every lookup requires exactly one semantic sentinel row even when the requested record is absent.
Clean end of stream before that row is inspection failure.
The adapter accepts at most one decoded account or cursor result and validates exact column types and value forms.
The driver still buffers successful bodies, lines, rows, and values before these checks, so this logical bound does not close `TURSO-005`.

The Turso implementation permits these operations only on credential-free literal IPv4 or IPv6 loopback HTTP endpoints.
Credentialed and non-loopback handles reject the operation before connection acquisition or any persistence request.
The operations have an adapter-owned deadline that preserves a shorter caller deadline.
No retry loop, goroutine, background task, provider request, secret lookup, runtime wiring, or capability change is added.
Complete invocation and stream close are not claimed bounded.

## Security and risk impact

`TURSO-001` remains open because a protocol-provided `base_url` can change authority or scheme.
Credential-free literal-loopback restriction prevents a bearer token or production endpoint from entering this slice.

`TURSO-002` remains open because remote diagnostics can contain SQL and values.
Every account and cursor failure returned through the repository boundary uses a fixed category and optionally preserves only standard context cancellation identity.

`TURSO-003` remains open because close and completion behavior cannot be fully bounded or proven from the driver acknowledgement.
One mutation attempt, separate durable visibility, no replay, fresh reconciliation, and session discard contain uncertain outcomes.

`TURSO-004` remains open because the driver owns its HTTP client, redirect behavior, and transport policy.
The slice remains credential-free and literal-loopback only.

`TURSO-005` remains open because response allocation occurs before repository validation.
Tests prove bounded semantic acceptance and rejection after buffering but do not claim a pre-allocation byte bound.

Provider subjects and history IDs are sensitive even in this minimal model.
The implementation never logs or includes them in errors, runtime output, HTTP, CLI, health, capability, or MCP surfaces.
All repository fixtures use synthetic values.

## Alternatives considered

### Use account email as identity

Email addresses can change and disclose more personal data than the stable provider subject.
The selected model uses an opaque internal primary key and binary-unique provider subject.

### Store account lifecycle, display, token, or synchronization metadata now

Those fields require encryption, OAuth, lifecycle, and synchronization decisions that belong to later vertical slices.
The selected migration contains only the minimum identity and cursor state.

### Expose a generic transaction callback

A generic callback would spread SQL and transaction authority beyond the adapter and could bypass cursor rules.
The selected boundary exposes one typed cursor commit operation.

### Retry uncertain writes automatically

The driver cannot prove whether an interrupted mutation became durable.
Automatic replay would weaken at-most-once behavior, so the selected design stops and requires explicit fresh reconciliation.

## Dependency and capability impact

This decision adds no direct, indirect, tool, test, runtime, Action, or container dependency.
Dependency-free catalog and value-boundary tests preserve the exact byte-length and embedded-NUL guards, while the pinned-driver contract proves those exact migration bytes are sent.
The exact `tursogo-serverless` pin and module checksums remain unchanged.
No CLI, HTTP, MCP, health, capability, configuration, OAuth, Gmail, or runtime activation surface changes.
No owner credential, database URL, token, provider identifier, or live account is required.

## Deletion and rollback impact

No pre-existing file is deleted, renamed, truncated, or replaced.
Migration `0001` remains byte-for-byte unchanged.
Because migration `0002` is append-only, rollback is an application rollback that stops using the typed operations rather than a destructive schema downgrade.
Only the repository owner may authorize a later destructive database migration or file deletion.

## Consequences

Synthetic callers can now establish stable Gmail account identity and commit monotonic Gmail history cursors through a replaceable typed storage contract.
The no-SQL fake supports higher-layer credential-free tests.
The exact pinned driver is exercised through literal-loopback protocol fixtures without credentials.
Live Turso access, runtime persistence, OAuth enrollment, provider credentials, account lifecycle state, message persistence, and production writes remain absent.
