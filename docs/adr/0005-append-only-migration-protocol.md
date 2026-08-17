# ADR 0005: Apply append-only migrations only through credential-free loopback

- Status: Accepted with known risks
- Date: 2026-08-17
- Issue: #20
- Owners: @mandloideep
- Extends: [ADR 0004](0004-turso-serverless-adapter.md)

## Context and need

InboxGate needs a deterministic schema boundary before account or synchronization state can be stored.
Concurrent starts, changed historical SQL, partial failures, and uncertain remote acknowledgements can otherwise leave schema state unverifiable.

The selected Turso driver retains the unresolved authority, diagnostic, cancellation, client-policy, and successful-response limits accepted in ADR 0004.
This decision therefore permits migration behavior only against a credential-free literal-loopback endpoint and does not activate Turso Cloud or runtime persistence.

## Decision

InboxGate stores reviewed migrations as embedded files named `NNNN_lowercase_slug.sql`.
The sequence starts at `0001`, is contiguous, and is limited to 256 files, 256 KiB per file, and 4 MiB in total.
The catalog rejects invalid names, missing or duplicate numbers, empty files, invalid UTF-8, NUL bytes, and exceeded bounds before acquiring a database connection.
Each lowercase SHA-256 checksum is computed over the exact embedded bytes without newline normalization.

Migration `0001_migration_ledger.sql` creates `inboxgate_schema_migrations` with only a bounded integer migration number and a 64-character lowercase checksum.
No account, cursor, message, OAuth, review, gate, audit, or backfill table is part of this decision.

The storage handle exposes one `Migrate` operation with a result containing only bounded applied and current counts.
It accepts no SQL, path, migration list, checksum, database handle, or SDK value from a caller.
The operation rejects every credentialed endpoint and every non-loopback endpoint before acquiring a connection or issuing a migration request.
It remains unreachable from configuration, commands, service startup, health, capabilities, Gmail, OAuth, and MCP.

One invocation first inspects the ledger outside a transaction through a physical `database/sql.Conn`.
If work is pending, it reserves a connection and sends one bounded no-argument multi-statement string through the driver's `/v3/pipeline` `sequence` path.
That exact string contains fixed `BEGIN IMMEDIATE`, the reviewed embedded migration bytes, a transaction-local prefix guard, one ledger insertion, and fixed `COMMIT` in order.
The prefix guard uses a bounded temporary table with a fixed `CHECK` constraint to abort the transaction unless the locked ledger contains the exact total, contains no null number or checksum, and contains every expected number and checksum pair exactly once.
Migration `0001` creates the ledger before checking the empty prefix, while every later migration checks its complete expected prefix under the writer lock before inserting its own ledger row.
The guard literals are only bounded public catalog numbers and validated lowercase hexadecimal checksums.
The insertion literals are only the catalog's bounded integer migration number and validated lowercase hexadecimal checksum.
They are rendered by repository code, never supplied by a caller, and never contain user, provider, configuration, or database data.
It applies at most one pending migration per transaction.
Ledger inspection remains fixed and parameterized.
The runner never uses `database/sql.Tx` because the selected driver's transaction completion methods use internal background contexts.

The runner queries at most 257 ledger rows and validates every decoded number and checksum against the bounded catalog.
It rejects missing, unknown, noncontiguous, malformed, over-limit, or checksum-mismatched rows as drift.
A current ledger with the matching terminal marker returns a mutation-free result from the initial outside-transaction inspection without acquiring the writer lock.

The runner never automatically retries a transaction sequence, rollback, inspection, or dropped response.
The driver JSON-decodes pipeline responses and requires one result per request, but it does not validate the sequence response payload and accepts `get_autocommit: false` as a successful `ExecContext` result.
A pipeline response that the driver rejects, or any sequence that fails semantic terminal proof, causes a rollback attempt through a separate short cleanup context.
Missing or wrong sequence response payloads that this driver accepts still cannot produce success unless the independent ledger and marker proof passes.
The driver cannot prove that rollback reached terminal completion even when it returns nil, so every failed sequence returns a fixed unknown-outcome category.
The runner does not inspect raw remote text to guess which transaction stage occurred.
After every purportedly successful commit, the runner keeps the apply connection reserved and runs a second bounded no-argument sequence on that same session.
The second sequence uses a fixed savepoint, a bounded checksum self-assignment on the expected ledger row to acquire main-database writer serialization, and a transaction-local guard that revalidates the same exact null-rejecting ledger prefix and requires one nonnegative SQLite `PRAGMA user_version` value no greater than the target before setting the marker to the expected migration number and releasing the savepoint.
The self-assignment target is the bounded code-derived migration number and accepts no caller or database value as SQL text.
A separate physical connection must then observe both the exact durable ledger prefix and the expected `user_version` before the apply connection can return to the pool or the invocation can report success.
Marker visibility proves that the apply session was in autocommit before the savepoint probe, because a marker written inside an uncommitted outer transaction is not visible to the separate connection.
If the ledger committed but the process stopped before the marker became durable, a later explicit invocation repairs only the marker and does not replay schema SQL.
A marker ahead of the durable ledger, or a ledger prefix deleted or replaced concurrently after preflight inspection, is never overwritten and leads to unknown outcome or drift according to where it is observed.
If a response is incomplete, the ledger remains absent, or the marker is not independently visible, the invocation returns unknown outcome without replay and forcibly discards the apply connection from the pool after a bounded rollback attempt.
A concurrent sequence rejected after another runner acquires the writer lock attempts rollback and returns unknown because cleanup cannot be confirmed.
A later explicit invocation with a fresh handle reconciles the durable ledger and applies work only when inspection proves it is absent.

Every returned migration error is repository-owned and bounded.
Caller cancellation remains discoverable through `errors.Is`, while SQL, arguments, checksums, URLs, tokens, paths, response bodies, protocol messages, and upstream diagnostics are omitted.

The migration invocation and context-aware statements have repository-owned deadlines.
The driver still controls successful-response buffering and stream close through behavior that InboxGate cannot fully bound.
This decision does not claim that the complete invocation or stream close is bounded under every driver failure.

## Accepted risks reached

- `TURSO-001` is reached because later migration requests can follow a protocol-provided `base_url` without repository-owned same-authority or no-downgrade enforcement.
- `TURSO-002` is reached internally, while the storage boundary replaces returned diagnostics with fixed categories.
- `TURSO-003` is partially contained by one context-aware atomic transaction sequence, same-session marker probing, separate durable verification, and forced pool discard when session state is unproven, but stream close and an unacknowledged sequence or rollback remain uncertain.
- `TURSO-004` is reached because the driver still owns redirect, transport, connection, and timeout policy.
- `TURSO-005` is reached because the driver buffers successful bodies, cursor lines, rows, and values before repository validation.

Credential-free contracts reproduce protocol-driven authority changes and redirect following.
They also prove bounded logical row and value rejection after the driver has buffered the successful response.
These tests document the limits and do not close any risk.

## Alternatives considered

### Use `database/sql.Tx`

This would use the driver's background-context `Commit` and `Rollback` methods and would weaken truthful cancellation semantics.
The context-aware pipeline sequences avoid those methods, and post-commit verification uses a separate physical connection while the apply connection remains reserved.

### Retry uncertain statements or commits

Automatic retry could apply reviewed schema SQL or a commit more than once after an ambiguous transport outcome.
The selected design stops and requires a new explicit invocation to inspect durable state.

### Add a migration framework

A framework would add a direct dependency and a broader SQL and filesystem surface for a small fixed catalog.
The standard library and handwritten runner provide the required behavior without changing the dependency graph.

### Activate remote migrations now

Credentialed remote execution would reach driver behavior that lacks required authority, redirect, response, and close controls.
Production activation remains blocked for a focused later decision and explicit owner approval.

## Dependency and removal impact

This decision adds no direct, indirect, tool, Action, container, or test dependency.
The exact `tursogo-serverless` pin and module checksums remain unchanged.

The migration runner is isolated behind `internal/storage` and can be removed with the Turso implementation without changing application callers.
No pre-existing file is deleted, renamed, truncated, or replaced.

## Consequences

Synthetic code can now establish and verify the migration ledger through the exact pinned driver without credentials.
Runtime persistence, live Turso access, account schema, and production migration approval remain absent.
Future schema issues must append new canonical files and may never edit an applied migration.
Before live credentials are permitted, a focused decision must recheck cross-authority and downgrade handling, raw diagnostics, transaction and close cancellation, redirect and transport policy, and successful-response byte limits.
