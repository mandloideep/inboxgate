# ADR 0012: Persist deterministic gate decisions

- Status: accepted for credential-free inert evaluation
- Date: 2026-08-18
- Issue: #34

## Context and need

InboxGate has a strict normalized message record and a validated gate policy, but it does not yet classify or durably identify the policy result for a message.
A later review queue must not reinterpret policy from mutable configuration, accept arbitrary explanation text, or treat an uncertain database response as permission to evaluate or mutate again.
The result must remain deterministic across processes and implementations while every message field and policy field that can affect the result is bound to one versioned identity.

The selected Turso driver remains subject to open risks `TURSO-001` through `TURSO-005`.
The adapter is still inert, and credential-free literal-loopback tests do not execute a remote Turso Database engine.

## Decision

Add a pure `internal/gate` classifier that imports only the Go standard library, `internal/config`, and `internal/mail`.
Add a separate `internal/gateeval` application service that composes the classifier with the repository-owned typed storage interface.
Storage imports the closed gate vocabulary but never imports the evaluator, which keeps package authority acyclic and prevents database behavior from entering classification.

Gate version 1 has exactly four outcomes: `ignore`, `metadata_only`, `review_candidate`, and `urgent_review_candidate`.
It has exactly ten bounded reason codes: `excluded_label`, `sender_block_domain`, `sender_allow_domain`, `bulk_category`, `mailing_list`, `automated_message`, `owner_candidate_term`, `owner_urgent_term`, `direct_recipient`, and `no_candidate_signal`.
Reason codes are unique, sorted by byte value, encoded as canonical compact JSON, and limited to 512 bytes.
They never contain message, address, subject, label, policy, credential, SQL, URL, or provider values.

Classification applies one fixed precedence.
An excluded label or blocked sender domain produces `ignore`.
An owner allow-domain signal combined with an owner urgent term produces `urgent_review_candidate`.
An owner allow-domain or owner candidate-term signal produces `review_candidate`, including when a bulk signal is also present.
Without an owner signal, a bulk category, mailing-list marker, or automated-message marker produces `metadata_only`.
A direct-recipient signal produces `review_candidate` only when enabled and no earlier rule applies.
Every other valid message produces `metadata_only` with `no_candidate_signal`.

Domain matching is ASCII case-insensitive and boundary-aware for an exact configured suffix or its subdomains.
A sender mailbox is parsed first, and its domain is the suffix after the final `@`, so a valid quoted local part can contain an earlier `@` without bypassing domain policy.
A block-domain match always wins over an allow-domain match.
Malformed sender addresses do not match policy domains.
Subject terms use literal Unicode case folding without regular expressions or Unicode normalization.
Each subject-term list rejects Unicode case-fold-equivalent duplicates through the same canonical simple-fold representation used for matching.
The matcher creates one canonical Unicode simple-fold subject, folds each bounded term once, and performs at most 512 searches over a folded subject of at most 16,384 bytes with each folded term limited to 512 bytes.
Labels and configured categories use exact byte matching.
Missing optional metadata is absence, not permission to infer an owner signal.

The classifier returns the existing canonical message metadata hash as `source_metadata_hash`.
It derives `input_hash` with SHA-256 over the bytes `inboxgate/gate-input/v1`, one NUL byte, the big-endian unsigned gate version, the length-prefixed source metadata hash, the two policy booleans in schema order, and all six policy lists in schema order.
Each policy list is represented by its length-prefixed field tag, big-endian element count, and length-prefixed byte-sorted values.
The policy lists are `excluded_labels`, `suppress_gmail_categories`, `sender_allow_domains`, `sender_block_domains`, `subject_candidate_terms`, and `subject_urgent_terms`.
This framing is injective within the accepted field bounds, independent of YAML list order, and changes when any policy or canonical metadata input changes.

Append migration `0006_gate_decisions.sql` without modifying migrations `0001` through `0005`.
The strict `WITHOUT ROWID` table stores one row per canonical message record ID with the gate version, source metadata hash, input hash, outcome, canonical reason JSON, and bounded evaluation timestamp.
The record ID is a binary-collated primary key and a restrictive foreign key to the canonical message row.
The schema restricts fixed hashes, version bounds, outcome vocabulary, reason JSON size, timestamp range, and NUL bytes without depending on SQLite JSON functions.
Application decoding enforces the complete reason vocabulary and canonical JSON form before any row crosses the storage boundary.

Expose only typed storage reads and a typed compare-and-swap decision commit.
A read reports whether the persisted decision still refers to the current canonical message metadata.
An insert requires no existing decision, and a replacement requires the exact prior version and input hash.
An exact existing semantic result is idempotent and retains its first evaluation timestamp.
The same input identity with different semantic output is a conflict.
A stale source message, stale expected revision, malformed durable row, missing account, missing message, and uncertain mutation outcome each map to fixed repository errors without sensitive values.

The Turso adapter uses one fixed two-parameter lookup statement and one fixed twelve-parameter mutation statement.
The mutation joins the canonical message by record ID, account ID, Gmail message ID, and source metadata hash, and applies insert or exact compare-and-swap conditions in the same database statement.
Every mutation is attempted at most once per invocation.
The mutation connection remains reserved while a separate physical connection proves the exact resulting durable state.
An unproven mutation session is discarded, the mutation is never replayed in that invocation, and unresolved visibility returns recovery-required.
A fresh explicit invocation reads durable state before considering a new mutation.

The evaluator validates and copies policy at construction.
For one validated account and message ID, it reads the canonical message and any prior decision, classifies the current message, returns an exact existing decision without reading the clock, or commits one new decision with the exact prior revision when replacement is required.
After a reported commit success, it fresh-reads and returns the exact durable decision so a concurrent idempotent winner retains its authoritative first-evaluation timestamp.
It never queries Gmail, advances a cursor, schedules work, or exposes a runtime caller.

## Alternatives considered

Keeping decisions only in memory would lose evaluation identity and the original timestamp across restart.
It would also leave no durable recovery point after an uncertain database response.

Storing policy YAML or an arbitrary explanation object would broaden sensitive retention, create parser ambiguity, and permit unbounded or user-controlled diagnostics.
The selected schema stores one closed semantic result and the versioned input digest only.

Recomputing decisions during every read would silently reinterpret historical results after a policy change.
The selected evaluator uses an exact prior revision and persists the new deterministic result explicitly.

Using a transaction callback or caller-provided SQL would broaden database authority beyond the typed storage boundary.
The selected adapter owns two fixed statements and one bounded proof protocol.

Retrying a mutation after a dropped or malformed response could apply a later compare-and-swap against state created by the uncertain attempt.
The selected protocol performs no same-invocation replay and requires separate physical proof.

## Dependency and supply-chain review

No direct, indirect, tool, Action, container, SQL-mock, JSON-SQL, or ambient-executable dependency is added or changed.
The Go standard library, existing fake, existing adapter, and pinned `tursogo-serverless` module are sufficient.
Module files, checksums, notices, workflow pins, and container inputs remain unchanged.
Removal stops calling the inert evaluator and leaves append-only migration history and durable rows intact.

## Security and privacy impact

Canonical email metadata, hashes, outcomes, and evaluation timestamps are sensitive stored data.
The classifier treats sender addresses, recipients, subjects, labels, and selected headers as untrusted data only.
Email content can match configured policy but cannot authorize Gmail mutation, database authority, configuration changes, tool use, or credential disclosure.

The slice adds stored derived decision state and updates `docs/threat-model.md` for that retention and integrity boundary.
It adds no secret, encryption key, authentication, network listener, outbound request, Gmail method, OAuth operation, raw SQL surface, shell execution, URL fetch, HTTP API, CLI command, MCP tool, scheduler, log, metric, health output, or capability.
Gmail remains read-only, and no provider request is made.

`TURSO-001` remains open because a protocol response can change scheme or authority.
`TURSO-002` remains open because upstream diagnostics can contain SQL and sensitive values.
`TURSO-003` remains open because completion and stream close remain uncertain.
`TURSO-004` remains open because the driver owns redirects and transport policy.
`TURSO-005` remains open because successful responses can allocate before repository bounds are applied.
Fixed diagnostics, parameterized SQL, one mutation attempt, separate physical proof, no replay, strict decoding, and session discard contain these risks without closing them.

## Rollback and removal

No pre-existing file is deleted, renamed, truncated, or replaced.
Migrations `0001` through `0005` remain byte-identical.
Migration `0006` is append-only, so application rollback stops using the typed gate operations and leaves the schema and historical data intact.
Only the repository owner may authorize a destructive schema downgrade or file removal.

## Consequences

Credential-free callers can classify synthetic normalized messages deterministically and persist one bounded current result through fake or literal-loopback storage.
Policy changes and metadata changes produce new input identities and require exact compare-and-swap replacement.
Restart and uncertain-response behavior is explicit and does not duplicate a mutation attempt.

The classifier and evaluator remain inert because no executable or capability calls them.
Live Turso use, Gmail access, credentials, deployment, and production migration remain prohibited pending separately approved owner gates.

## Validation

The preserved tests-only red commit predates this decision and all production implementation.
Tests cover the closed vocabulary, fixed precedence, boundary-aware domains, literal Unicode folding, ambiguity handling, complete sorted reasons, defensive copies, known hash vectors, every policy field, metadata changes, canonical durable decoding, fake compare-and-swap races, evaluator restart and metadata races, exact migration bytes and checksum, exact driver parameters, uncertain response modes, cancellation, malformed rows, error disclosure, and all `TURSO-001` through `TURSO-005` containment regressions.
Focused tests, race tests, storage and migration tests, `make check`, diff validation, dependency and capability inventories, and CGO-disabled release-target builds must pass before merge.
