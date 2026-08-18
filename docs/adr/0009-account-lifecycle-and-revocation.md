# ADR 0009: Persist a versioned account lifecycle before provider revocation

Status: accepted for credential-free synthetic execution

Date: 2026-08-17

Issue: #28

## Context

InboxGate needs bounded account listing, operator pause and resume, trusted reauthorization markers, and fail-closed OAuth grant revocation before Gmail synchronization can be enabled.
Enrollment currently proves account, cursor, and encrypted credential durability but has no durable activation state.
A provider revocation request is externally observable and cannot participate in the database transaction that records local intent.
The selected Turso driver remains pinned under ADR 0004 with unresolved risks `TURSO-001` through `TURSO-005`.

## Decision

### Durable lifecycle

Append `0004_account_lifecycle.sql` without changing any byte of migrations `0001` through `0003`.
The strict lifecycle table contains only account ID, state, state version, optional reauthorization reason, and revocation status.
Valid states are `pending`, `active`, `paused`, `reauthorization_required`, and `revoked`.
State versions are SQLite integers from 1 through `9223372036854775807` and every successful non-idempotent transition increments the version exactly once.
Valid reauthorization reasons are `refresh_invalid_grant`, `refresh_admin_policy_enforced`, `gmail_unauthorized_after_refresh`, and `gmail_domain_policy`.
A reason is present exactly when the state is `reauthorization_required`.
Revocation status is `none` outside the revoked state and is `pending`, `attempting`, `confirmed`, or `manual_action_required` in the revoked state.

The migration backfills an existing account as active only when both a synchronization cursor and provider credential exist.
Every other existing account is backfilled pending.
An `AFTER INSERT` trigger creates a pending version 1 lifecycle row for every later account.
The trigger and foreign key keep lifecycle creation inside the account insertion transaction.

The allowed graph is pending to active after complete-state proof, active to paused, paused to active after complete-state proof, active to reauthorization-required with one typed reason, and every non-revoked state to revoked with pending revocation.
A revoked pending row may advance only to revoked attempting.
A revoked attempting row may advance only to revoked confirmed or revoked manual-action-required.
Revoked is otherwise terminal.
Repeated pause, resume, or finalized revocation is handled as an idempotent application result and does not increment the durable version.
Revocation reserves the complete remaining version budget before mutation: three increments for a non-revoked row, two for revoked-pending, and one for revoked-attempting.
A nonterminal row without that budget fails closed before credential access, mutation, or provider contact.
A terminal confirmed or manual-action-required row needs no further lifecycle increment, so it reconciles residual ciphertext even at the maximum version.

### Typed storage boundary

The repository-owned storage handle adds only bounded account summaries, one lifecycle lookup, one typed lifecycle compare-and-swap, and one revoked-only exact credential compare-and-delete operation.
The boundary exposes no raw SQL, generic state string, generic update, transaction callback, driver type, provider response, or credential plaintext.
Account listing is ordered by binary account ID, requests at most 101 rows, rejects more than 100, and returns only account ID, fixed provider, lifecycle fields, and cursor and credential presence booleans.

Lifecycle mutation uses one fixed parameterized statement with exact expected state, revocation status, and version.
Activation and resume require cursor and credential existence in the same statement that changes the lifecycle row.
Each mutation is attempted once and keeps its physical connection reserved until a separate physical connection observes the exact requested durable state.
An acknowledgement or terminal state that cannot be proven returns a fixed unknown-outcome category, discards the mutation session, and is never replayed in the same invocation.
A later explicit invocation may reconcile the durable state.

Credential deletion uses one fixed parameterized statement with the exact expected ciphertext and an existing revoked lifecycle row.
It is unavailable for every non-revoked account and cannot blind-delete or delete a different ciphertext.
The mutation connection remains reserved until a separate physical connection proves credential absence.
An unproven session is discarded without same-invocation replay.

The no-SQL fake applies the same graph, completeness, version, idempotency, and exact-delete rules under one mutex.
The exact pinned-driver fixture remains credential-free and literal-loopback and supplies wire, response, uncertainty, concurrency, session-discard, and reconciliation evidence without claiming to execute SQLite.
Dependency-free catalog and wire tests assert the exact migration constraints, but the literal-loopback fixture does not execute SQLite.

### Enrollment and operator behavior

Enrollment checks the lifecycle before changing a cursor or credential.
Pending enrollment may complete its staged cursor and encrypted credential work and becomes active only after a fresh complete-state and decryption proof.
A complete pending restart activates without replacing cursor or credential state.
Active is idempotently complete.
Paused, reauthorization-required, and revoked accounts reject enrollment without changing cursor or credential state.

The operator surface adds bounded `account list`, `account pause`, `account resume`, and confirmed `account revoke` commands.
Listing emits one canonical versioned JSON document no larger than 64 KiB and documents that account IDs are sensitive.
Pause and resume emit fixed success lines.
Revocation emits one fixed confirmed line or one fixed owner-action line.

List, pause, and resume resolve only the selected database endpoint and optional database token after environment-selector separation.
Revocation resolves the selected master key only after a durable revoked-attempting claim exists and a fresh read proves that an encrypted credential is present.
These commands never resolve Google OAuth client values, redirect values, or the MCP token.
All persistence execution remains restricted to credential-free literal-loopback endpoints, so live Turso activation remains prohibited.

### Fail-closed provider revocation

The production Google revocation endpoint is fixed to `https://oauth2.googleapis.com/revoke`.
Only same-package tests may substitute a credential-free literal-loopback endpoint.
The request is one form-encoded HTTPS POST with the refresh token only in the request body.
The token is absent from the URL, query, headers, cookies, diagnostics, and output.
The client owns a fresh proxy-disabled transport with verified TLS, explicit dial and response-header bounds, redirect rejection, a 15-second operation deadline, and a 16,384-byte response limit.
There is no retry.

Revocation first durably records revoked-pending intent, then claims that intent through an exact pending-to-attempting compare-and-swap.
Only the process that receives a proven one-row acknowledgement for that claim may freshly read the exact encrypted credential, decrypt it, and make at most one provider request.
Credential initialization or replacement atomically rejects every revoked lifecycle, so no ciphertext can be inserted after revocation intent becomes durable.
Only exact HTTP 200 produces confirmed status.
HTTP 400, every other status, malformed or oversized response behavior, request failure, missing credential, unknown key, authentication failure, and cancellation produce manual-action-required status or a recovery-required result according to durable proof.
An unproven credential inspection after the attempting claim returns recovery-required without finalizing, because no exact ciphertext is available for safe deletion.
Provider failure and caller cancellation use an independent bounded cleanup context to finalize the lifecycle and exact compare-delete the local credential.

A restart at revoked pending may make one provider attempt only after winning a new durable attempting claim.
A restart at revoked attempting treats provider completion as ambiguous, never calls the provider again, finalizes manual-action-required, and exact-deletes any remaining ciphertext.
A restart at confirmed or manual-action-required never calls the provider and only reconciles any exact remaining ciphertext deletion.
Concurrent callers and separate processes converge through the status-and-version compare-and-swap so only one proven claimant may cross the provider boundary.
This design prioritizes at-most-once provider crossing over automatic retry after an ambiguous crash.

## Accepted risks reached

`TURSO-001` remains open because a protocol-provided `base_url` can change authority or scheme.
The credential-free literal-loopback restriction prevents a database bearer token from entering this slice but does not add same-authority enforcement.

`TURSO-002` remains open because driver diagnostics can contain SQL, lifecycle values, account IDs, and ciphertext.
Every lifecycle and deletion failure crossing the repository boundary is a fixed bounded category.

`TURSO-003` remains open because request completion and stream close cannot be fully bounded or proven.
One mutation attempt, separate physical visibility, no replay, fresh reconciliation, and forced session discard contain uncertain outcomes.

`TURSO-004` remains open because the driver owns its private HTTP client and redirect policy.
Storage remains credential-free literal-loopback, while the separate Google revocation client is repository-owned and redirect-rejecting.

`TURSO-005` remains open because successful storage responses can be buffered before repository validation.
The repository bounds accepted lifecycle rows, values, summaries, and output after buffering without claiming a pre-allocation bound.

## Alternatives considered

### Delete the credential before provider revocation

Deleting first would remove the only local material capable of revoking the provider grant after a crash.
Durable intent therefore precedes the provider boundary and local deletion follows a proven final outcome.

### Call the provider before persisting intent

A crash after the provider call could leave an active local account with an externally revoked grant and no reliable restart decision.
Persisting pending intent and separately proving the attempting claim makes every provider call restart-visible without authorizing a retry after ambiguous completion.

### Put provider revocation inside a database transaction

An external HTTP request cannot be committed atomically with Turso state and would hold a database writer while waiting on an untrusted service.
The selected staged protocol uses durable intent and versioned reconciliation instead.

### Add a general lifecycle or provider framework

A generic framework would expose broader transition and external-request authority than the Gmail-only first release requires.
The selected code uses fixed Gmail behavior and typed lifecycle operations only.

## Dependency and capability impact

This decision adds no direct, indirect, tool, test, runtime, Action, container, or ambient executable dependency.
It uses the Go standard library, the existing cryptobox, and the already pinned Turso driver behind the repository-owned adapter.
The exact module graph and checksums remain unchanged.

The capability registry does not change and `gmail.read` remains disabled.
The health-only service, MCP surface, scheduler, Gmail message access, and Gmail mutation surface remain unchanged.
No live credential, account, provider, database, or production URL is required.

## Security and privacy impact

Account IDs, lifecycle state, presence booleans, ciphertext, and provider outcomes are sensitive.
Operator output contains account IDs only on the explicit list surface and documents that they must not be shared.
Errors, logs, provider requests, callback responses, health, capabilities, and documentation contain no token, subject, email, ciphertext, endpoint, or raw provider body.

Google grant revocation is an intentional credential action but does not mutate Gmail messages, labels, read state, or mailbox content.
The implementation cannot send, delete, archive, forward, label, or mark mail as read.

## Deletion and rollback impact

No pre-existing file is deleted, renamed, truncated, or replaced.
Migrations `0001`, `0002`, and `0003` remain byte-for-byte unchanged.
Migration `0004` is append-only, so application rollback stops exposing lifecycle commands rather than destructively downgrading the database.
Only the repository owner may authorize a later destructive migration or file deletion.

## Consequences

Synthetic operators can list, pause, resume, mark reauthorization, and revoke accounts through a deterministic durable lifecycle.
Enrollment gains a final activation boundary and cannot silently reauthorize a paused, reauthorization-required, or revoked account.
Provider revocation remains staged and fail-closed across restarts without claiming cross-system atomicity or automatic provider retry after an ambiguous crash.
Live Turso, live Google revocation, deployment, Gmail synchronization, MCP, and production secret use remain prohibited pending separate approval.

## Validation

Tests cover exact migration bytes, backfill and trigger structure, typed values, every allowed and forbidden transition, completeness proof, idempotency, full revocation version-budget boundaries, maximum-version terminal cleanup, bounded ordered listing, exact credential deletion, concurrency, cancellation, fixed diagnostics, and restart reconciliation.
Exact pinned-driver tests cover fixed SQL and arguments, separate physical visibility, uncertain acknowledgements before and after durability, session discard, no replay, malformed and oversized results, endpoint restriction, and all open Turso risks reached by this surface.
Provider tests cover exact request shape, one request, redirect rejection, status classification, body bounds, cancellation, no retry, durable-intent ordering, local deletion, missing and undecryptable credentials, and concurrent callers.
CLI tests cover exact grammar, exit codes, canonical bounded JSON, fixed messages, secret-selector separation, process output, and credential-free loopback end-to-end behavior.
Run focused tests with high repetition, race tests, `make check`, `git diff --check`, dependency and protected-migration diffs, em dash scan, and a clean worktree before review.
