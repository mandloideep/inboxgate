# ADR 0007: Version and authenticate provider credentials before persistence

Status: accepted for credential-free synthetic execution

Date: 2026-08-17

## Context

InboxGate must retain Gmail OAuth refresh tokens across restart without storing plaintext provider credentials.
The OAuth enrollment slice is not yet implemented, so this decision must establish encryption and ciphertext persistence without resolving an environment variable, contacting Google, using Turso credentials, or activating runtime behavior.
The storage implementation remains behind ADR 0004 with open risks `TURSO-001` through `TURSO-005`.
ADR 0005 provides append-only migrations, and ADR 0006 provides the minimum account identity that authenticated credential binding requires.

Provider credentials are high-value secrets before encryption and remain sensitive after encryption.
The format must support deterministic validation, key identification, restart, controlled rotation, rollback, and independent recovery without creating a generic cryptography framework.
Storage must be incapable of accepting plaintext through its typed interface.

## Decision

### Cryptographic construction

`internal/cryptobox` implements only Gmail OAuth refresh-token encryption with Go standard-library AES-256-GCM.
Every key is exactly 32 bytes.
Every encryption reads a complete fresh 12-byte nonce through `io.ReadFull` from `crypto/rand.Reader`.
AES-GCM supplies a 16-byte authentication tag.
Plaintext is arbitrary binary data from 1 through 4096 bytes.

Authenticated additional data is the exact binary envelope header followed by NUL, `gmail`, NUL, `oauth_refresh_token`, NUL, and the exact 32-character lowercase hexadecimal internal account ID.
The header therefore authenticates the format version, algorithm, and key identifier, while the remaining additional data prevents moving an envelope between accounts, providers, or purposes.
No fallback algorithm, provider, purpose, account binding, nonce size, tag size, or unauthenticated legacy format is accepted.

The same-package test seam can replace the random reader for deterministic known-answer and fault tests.
Production callers cannot select a nonce or random source.

### Canonical keyring

The keyring is a bounded canonical text value with this grammar.

```text
igk1:<active-id>=<unpadded-raw-URL-base64-32-byte-key>[,<decrypt-id>=<unpadded-raw-URL-base64-32-byte-key>...]
```

Key identifiers match `[a-z][a-z0-9_-]{0,31}`.
The first entry is active for encryption.
Any remaining decrypt-only entries are sorted in bytewise identifier order.
The parser accepts one through eight entries and at most 620 input bytes.
Every key text is the canonical 43-character unpadded raw URL-safe base64 encoding of exactly 32 bytes.
Duplicate identifiers, duplicate key bytes, whitespace, padding, alternate encodings, unsorted decrypt entries, unknown versions, and trailing data fail with one fixed invalid-keyring category.

The keyring owns copied key arrays.
Close overwrites those repository-owned arrays, decoded key buffers are overwritten after copying, and rotation overwrites temporary plaintext after use.
Go does not guarantee removal of copies held in registers, stack growth, compiler temporaries, garbage-collected memory, or cryptographic library internals, so this decision does not claim complete zeroization.

### Ciphertext envelope

The binary envelope contains these fields in order.

```text
magic "IGC\x00" | version 1 | algorithm 1 | key-id length | key-id | 12-byte nonce | ciphertext and 16-byte tag
```

The text representation is `igc1.` followed by canonical unpadded raw URL-safe base64 of the complete binary envelope.
The accepted text length is 55 through 5556 bytes.
Parsing validates every structural field, key identifier, encoded length, plaintext-derived ciphertext bound, and canonical encoding before decryption.
Unknown key identifiers return a fixed unknown-key category.
Authentication failure returns a fixed authentication category.
No returned error contains plaintext, ciphertext, account ID, key bytes, nonce, tag, provider data, or underlying cryptographic diagnostics.

An envelope already encrypted under the active key is rotation-idempotent and remains byte-identical.
An envelope using a retained decrypt-only key is decrypted and re-encrypted with a fresh nonce under the active key.
Removing an old key before every durable envelope has been rotated and verified makes those envelopes unavailable, so removal is an explicit later operator step rather than automatic cleanup.

### Ciphertext-only persistence

Append `0003_provider_credentials.sql` without modifying migrations `0001` or `0002`.
The new strict table contains only the account ID primary and foreign key, a key identifier with binary collation, and the ciphertext envelope with binary collation.
The schema uses BLOB byte lengths and explicit embedded-NUL rejection for all durable text.
It enforces the account ID form, key identifier bounds and alphabet, ciphertext length, `igc1.` prefix, and raw URL-safe base64 alphabet.
These database checks are structural containment and do not replace AES-GCM authentication.

The repository-owned storage handle exposes only typed credential lookup and compare-and-swap commit.
The typed envelope parser derives its key identifier from the authenticated-envelope header structure before persistence.
No storage method accepts plaintext bytes, a generic value, caller-selected SQL, a transaction callback, a delete, or a blind overwrite.

Initialization requires an absent durable credential and a nil expected envelope.
Replacement requires the exact current ciphertext envelope as the expected value.
An already durable next envelope is idempotent success.
A missing account, stale expected envelope, blind replacement, or crossed concurrent writer is rejected with a fixed category.
The fixed replacement statement keeps a source row when the expected envelope is nil or when the same account currently has the exact non-nil expected envelope, then repeats the exact expected-envelope guard on the conflict update.
This shape prevents a non-nil expected value from initializing an absent row while allowing an exact matching replacement and preventing stale overwrite.

Lookup and mutation use fixed parameterized SQL and bounded validated values.
Every lookup requires exactly one semantic sentinel row, including absence.
The adapter rejects missing, malformed, duplicated, excessive, mismatched, NUL-containing, or oversized decoded values.
The driver can allocate an oversized successful value before repository validation, so this does not close `TURSO-005`.

Each invocation attempts the credential mutation at most once.
The mutation connection stays reserved while a separate physical connection verifies the exact durable next envelope.
Exact separate visibility is success authority even if the mutation acknowledgement was dropped or malformed.
Only an exact one-row affected acknowledgement plus exact visibility permits the mutation session to return to the pool.
A missing step completion or zero-row acknowledgement forces session discard even when separate visibility authorizes successful reconciliation.
Any unproven durable state returns a fixed unknown-outcome category, discards the mutation session, and is never replayed in the same invocation.
A fresh explicit invocation may reconcile an already durable next envelope or attempt an absent value once.

The dependency-free literal-loopback protocol fixture exercises the exact pinned driver, exact statement and argument bytes, response decoding, durable visibility, and session lifecycle but does not execute SQLite.
The fixed SQL shape and reviewer-supplied direct SQLite reproduction provide the current semantic evidence without adding an ambient executable or test dependency.
Live or remote engine validation remains prohibited until a later approved activation issue supplies a pinned credential-free engine boundary.

Credential persistence remains restricted to credential-free literal IPv4 or IPv6 loopback HTTP endpoints.
Credentialed and non-loopback handles reject it before connection acquisition.
No configuration, environment, CLI, HTTP, MCP, OAuth, Gmail, health, capability, service-startup, or production path reaches the cryptobox or credential store.

## Rotation, rollback, backup, and recovery

A future approved rotation workflow creates a new unique 32-byte key inside the approved secret manager and places it first in the keyring.
Every prior key needed by a durable envelope remains as a sorted decrypt-only entry.
The workflow re-encrypts each credential through exact ciphertext compare-and-swap, verifies all durable envelopes after a fresh process restart, and removes an old key only after no durable envelope references it.

Application rollback restores the previously backed-up application version and exact canonical keyring together.
Database rollback does not edit or downgrade migration `0003`.
Recovery restores the Turso database and the independently protected canonical keyring from separate systems, starts a fresh process, and verifies bounded credential reads before synchronization resumes.
Loss of a referenced key makes its credential unrecoverable from ciphertext alone.
Exposure of a referenced key can compromise every envelope encrypted under it, so the affected provider grants and encryption keys require owner-controlled rotation.

The owner must generate and store production key material only through the approved secret manager after runtime activation and a bounded operator workflow are separately approved.
No agent, issue, pull request, test, log, repository file, command argument, or chat receives the key value or a secret-derived hash, fingerprint, prefix, or suffix.

## Security and risk impact

`TURSO-001` remains open because a protocol-provided `base_url` can change authority or scheme.
The literal-loopback credential-free restriction and changed-authority regression prevent this slice from carrying a database bearer token, but they do not add same-authority enforcement.

`TURSO-002` remains open because driver diagnostics can contain SQL and values.
Credential lookup and commit return only fixed repository categories with optional standard context cancellation identity.

`TURSO-003` remains open because request completion and stream close cannot be fully bounded or proven.
One mutation attempt, separate durable visibility, no replay, fresh reconciliation, and forced session discard contain but do not eliminate uncertain outcomes.

`TURSO-004` remains open because the driver owns its private HTTP client and redirect policy.
Credential-free regressions record cross-authority and redirect behavior without claiming control.

`TURSO-005` remains open because successful response bodies, cursor lines, rows, and values can be buffered before validation.
The repository bounds accepted ciphertext rows and values and rejects oversized results after buffering.

## Alternatives considered

### Use an external cryptography package or secret-vault SDK

AES-GCM, secure randomness, canonical encoding, and fixed parsing are available in the Go standard library.
An external package would broaden the dependency and secret-handling boundary without satisfying a missing requirement in this slice.

### Derive per-account keys

Key derivation would add salt, derivation parameters, format evolution, backup, and rotation behavior that the current product does not need.
Account-bound authenticated additional data prevents ciphertext relocation while the bounded keyring provides explicit rotation.

### Store plaintext and rely on database encryption

Database encryption does not provide the required application-layer separation from database access, exports, backups, or operator mistakes.
The storage API therefore has no plaintext credential representation.

### Automatically retry uncertain credential writes

The driver cannot prove whether an interrupted implicit transaction became durable.
Automatic replay would weaken the explicit at-most-once contract, so the selected design stops and requires separate visibility or a fresh explicit invocation.

## Dependency and capability impact

This decision adds no direct, indirect, tool, test, runtime, Action, or container dependency.
It uses only Go standard-library cryptography and encoding packages and the already pinned Turso driver behind the existing adapter.
The exact module graph and checksums remain unchanged.

No CLI, HTTP, MCP, health, capability, configuration, OAuth, Gmail, provider, runtime, or deployment surface changes.
No live key, token, account, database, provider request, or production URL is required.

## Deletion and rollback impact

No pre-existing file is deleted, renamed, truncated, or replaced.
Migrations `0001` and `0002` remain byte-for-byte unchanged.
Migration `0003` is append-only, so rollback stops using the typed operation and restores compatible application and keyring versions rather than destructively downgrading the database.
Only the repository owner may authorize a later destructive database migration or file deletion.

## Consequences

Synthetic callers can encrypt, decrypt, restart, rotate, roll back, and recover bounded Gmail refresh-token bytes through a versioned account-bound envelope.
Higher layers can persist only validated ciphertext through a replaceable typed compare-and-swap contract.
Fake OAuth and Gmail enrollment work can now proceed without a live key or provider credential.
Runtime secret resolution, OAuth enrollment, live Turso access, production key generation, production writes, and deployment remain absent.
