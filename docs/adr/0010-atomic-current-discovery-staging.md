# ADR 0010: Finalize current discovery through durable staging

- Status: accepted for credential-free inert storage
- Date: 2026-08-18
- Issue: #30

## Context

InboxGate must persist normalized Gmail message metadata and advance the exact synchronization cursor as one atomic state change.
The existing cursor-only operation is restricted to enrollment initialization, rejects a present cursor or durable discovery attempt, and cannot advance an existing cursor outside the atomic discovery aggregate.
`CommitSynchronization` is therefore initialization-only and never accepts an expected present cursor.

The pinned `tursogo-serverless` driver cannot carry parameters in a multi-statement sequence.
Its `database/sql.Tx` completion path uses internal background contexts.
Provider-derived values therefore cannot be placed in a pipeline sequence, interpolated into SQL, or committed through the driver's transaction API while preserving the accepted bounded-outcome contract.

The selected driver remains subject to open risks `TURSO-001` through `TURSO-005`.
Credential-free literal-loopback protocol tests exercise the driver but do not execute the Turso Database engine or SQLite trigger semantics.

## Decision

InboxGate accepts a bounded durable staging state machine behind the repository-owned storage interface.
Migration `0005_current_discovery_atomic_commit.sql` appends canonical message, attempt, and staging tables plus write-only finalize and abort views.
An `INSTEAD OF INSERT` trigger on the finalize view performs canonical message promotion, exact cursor advancement, and staging cleanup inside one SQLite statement.

The application derives every message record ID from the validated account ID and Gmail message ID with a domain-separated full SHA-256 digest.
It derives every attempt ID from the exact expected and next cursors plus the sorted canonical message encoding.
Neither identifier is caller-selected, truncated, salted, retried, or placed in diagnostics.

One account can have at most one attempt.
An attempt is `open` while fixed-size parameterized chunks are staged and becomes `sealed` only after a fresh bounded inspection proves its complete manifest.
Open or sealed staging does not change canonical messages or the synchronization cursor.

The staging statement has 64 fixed slots and exactly 514 positional parameters.
Unused final slots carry `present = 0` and null non-control values and cannot reach a durable row.
The aggregate accepts no more than 5,000 unique messages or 16,777,216 bytes of canonical length-prefixed message encoding.
The maximum serialized stage request is 40 MiB.
Exact-driver tests commit the published 500-message and 5,000-message limits through 8 and 79 requests and inspect every argument position, protocol type, and final padding value.

Each attempt stores the lowercase hexadecimal encoding of the exact manifest preimage used by Go: the manifest domain, a NUL byte, the big-endian message count, and every ordinal-ordered canonical row encoding.
The SHA-256 manifest hash remains an application identifier, while the schema-verifiable manifest witness is the database authority for exact staged-field integrity.
Each staging row stores the lowercase hexadecimal encoding of its exact canonical row bytes.
The attempt witness is exactly `78 + 2 * encoded_bytes` characters and is bounded at 33,554,510 characters.
The fixed staging statement computes each row witness from live columns with documented scalar functions and does not add a parameter.
All row witnesses together can add another 33,554,432 bytes of hexadecimal text per maximum attempt.
The two witness layers therefore add at most 67,108,942 bytes before live staging fields, indexes, and database overhead.

Schema triggers require attempts to be inserted open, keep attempt identity and witness fields immutable, allow only an exact open-to-sealed transition, and reject every staging update.
Seal and finalize reconstruct each row witness from live columns and reconstruct the complete ordinal-ordered attempt witness with `group_concat` over an ordered subquery.
An exact retry can confirm an existing row but cannot rewrite it.
This closes the inspection-to-finalization race without adding another durable object beyond the approved messages, attempts, staging, finalize, and abort boundary.

Finalization uses exactly one fixed parameterized insert into the write-only finalize view.
Before that insert, the adapter decodes and re-encodes each canonical metadata value, verifies its metadata SHA-256, and verifies the record ID derived from the account and Gmail message IDs.
The trigger requires the exact sealed attempt and submitted manifest hash, active lifecycle, expected cursor, complete ordinal and byte manifest, immutable witness match, stable thread identity, and collision-free canonical keys.
The trigger does not recompute SHA-256-derived identities.
It inserts or updates only bounded mutable metadata, advances the exact cursor, and deletes only that attempt's staging state.
Any failed guard or durable constraint rolls back all trigger effects.

Every mutation is attempted at most once per invocation.
The mutation connection remains reserved while a separate physical connection inspects exact durable state.
An unproven session is discarded and the mutation is not replayed in the same invocation.
A later explicit invocation reconciles sealed durable state without contacting Gmail.

An exact open attempt with an unchanged expected cursor may be removed only through the fixed abort view.
Malformed, oversized, mixed, or cursor-divergent state is recovery-required and is not automatically deleted.
Pause and reauthorization-required retain bounded staging but prevent finalization.
The lifecycle transition to revoked deletes only noncanonical attempt and staging rows in the same lifecycle statement.
Canonical messages survive lifecycle changes.

Canonical reads return only complete normalized message metadata.
Every decoded database value is revalidated, re-encoded, hashed, and byte-compared before it crosses the storage boundary.
Open and sealed staging have no public read operation.

## Engine evidence limitation

Public tests use the Go standard library, the repository fake, dependency-free catalog inspection, and a literal-loopback SQL-over-HTTP model around the exact pinned driver.
The loopback model proves exact SQL bytes, argument order and types, request families, separate physical mutation and verification batons, session discard, deterministic modeled races, and no same-invocation mutation replay.
It does not prove remote Turso Database support for the 514-parameter statement, strict tables, triggers, constraint rollback, writer serialization, or concurrent finalization.

A supplementary local SQLite execution applies migrations `0001` through `0005` and proves that a direct sealed attempt insert fails.
It also proves that a staged row with a self-consistent wrong row witness cannot seal against the application manifest witness and that changing both a live field and its witness after seal fails the staging immutability trigger.
The same execution confirms that the cursor remains unchanged, no canonical message appears, and the sealed attempt and staging row remain available for recovery.
This evidence validates SQLite semantics without adding an ambient executable or SQL-mock dependency to public tests.

SQLite does not recompute SHA-256 and the schema does not defend an actor with arbitrary SQL authority who creates a completely self-consistent forged attempt and witness.
Application validation, the absence of any raw-SQL surface, and the remote activation gate contain that residual boundary.

Remote execution and runtime activation remain blocked.
A later approved activation issue must provide a pinned credential-free engine test or owner-approved sanitized evidence for the exact statement bound, ordered witness reconstruction, bounded allocation behavior, storage amplification, and atomic trigger behavior.
If the engine rejects those semantics, the project must select a smaller fixed chunk or another narrow atomic storage architecture without weakening cursor transactionality.

## Security and privacy impact

Gmail identifiers, thread identifiers, addresses, subjects, selected headers, labels, hashes, cursors, attempts, and staged records are sensitive attacker-controlled data.
They remain data only and never authorize behavior.
They do not enter SQL text, errors, logs, health, configuration output, capability output, CLI, HTTP, MCP, or documentation examples.

The slice stores no body, snippet, raw MIME, attachment bytes, link target, OAuth value, credential, raw provider JSON, or arbitrary header map.
Gmail remains read-only and no Gmail HTTP operation is added.

`TURSO-001` remains open because a protocol response can change scheme or authority.
`TURSO-002` remains open because upstream diagnostics can contain SQL and sensitive values.
`TURSO-003` remains open because completion and stream close remain uncertain.
`TURSO-004` remains open because the driver owns redirects and transport policy.
`TURSO-005` remains open because successful responses can allocate before repository bounds are applied.

Credential-free literal-loopback restriction, fixed diagnostics, fixed parameterized SQL, one mutation attempt, exact separate visibility, bounded accepted rows and values, no replay, and session discard contain these risks without closing them.

## Alternatives considered

### Compose message writes with `CommitSynchronization`

Separate operations can leave the cursor ahead of missing canonical messages after a partial failure.
This violates the core synchronization invariant.

### Use `database/sql.Tx`

The selected driver completes transactions with background contexts and cannot provide the required caller-bounded uncertain-outcome behavior.

### Send one multi-statement sequence

The driver's sequence endpoint does not carry parameters.
Rendering message or provider values into SQL would create an unacceptable injection and confidentiality boundary.

### Encode the batch as JSON for SQL parsing

JSON SQL functions add an engine assumption, broaden parsing authority, and weaken exact type and size proofs.
The selected design uses fixed typed positional values only.

### Keep staging only in memory

Memory-only staging cannot finalize after restart without fetching Gmail again and cannot distinguish a durable cursor outcome after an interrupted response.

### Expose a generic transaction callback

A generic callback would spread database and SQL authority beyond the repository adapter.
The selected interface exposes only the current-discovery aggregate, reconciliation, and one bounded message read.

## Dependency and capability impact

No direct, indirect, tool, Action, container, SQL-mock, JSON-SQL, or ambient-executable dependency is added.
The standard library, existing fake, existing adapter, and exact current Turso pin are sufficient.

The domain and storage surfaces gain normalized untrusted metadata and one typed atomic aggregate.
No Gmail adapter, OAuth refresh, scheduler, CLI, HTTP, MCP, audit, metric, health, configuration, capability-registry, or runtime activation behavior changes.
`gmail.read` and `gmail.current_sync` remain not implemented and cannot be enabled.

## Rollback and removal

No pre-existing file is deleted, renamed, truncated, or replaced.
Migrations `0001` through `0004` remain byte-identical.
Migration `0005` is append-only, so application rollback stops using the new typed operations and leaves the schema intact.
Only the repository owner may authorize a destructive schema downgrade or file removal.

The staging architecture can be removed from active code after a future accepted adapter supports context-aware parameterized transactions and every deployed attempt has been reconciled.
The append-only migration and historical data remain.

## Consequences

Credential-free callers can persist one bounded current-discovery batch and its cursor as an indivisible canonical state change.
Deterministic identifiers make exact retries and restart reconciliation stable across processes.
The later Gmail discovery slice can reconcile durable staging before contacting Gmail and can stop without cursor movement when its bounded page chain is incomplete.

Live Turso use, Gmail synchronization, credentials, deployment, and production migration remain prohibited pending their separately approved gates.
