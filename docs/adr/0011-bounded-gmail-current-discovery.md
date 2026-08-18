# ADR 0011: Bound Gmail current discovery behind one atomic commit

- Status: accepted for credential-free inert discovery
- Date: 2026-08-18
- Issue: #32

## Context and need

InboxGate can enroll one Gmail account, retain its refresh token as authenticated ciphertext, and atomically promote canonical message metadata with the corresponding history cursor.
No application use case currently composes those boundaries.
Ad hoc composition could advance an intermediate cursor, repeat uncertain provider or storage operations, confuse stale history with failed authorization, retain hostile provider data, or broaden Gmail access beyond the required read-only metadata.

The Gmail history API returns noncontiguous history IDs, repeated message additions, opaque page tokens, and an explicit final history ID.
An expired history cursor returns HTTP 404 and requires a later full synchronization.
The message metadata needed by `internal/mail` includes MIME attachment structure that the Gmail `METADATA` format does not provide.
The `FULL` format is therefore necessary, but its response projection must exclude message bodies, snippets, raw MIME, attachment bytes, and classification data.

The existing current-discovery storage aggregate is the only approved cursor-advancement path after enrollment.
It requires a complete bounded page chain and every normalized non-vanished message before it stages or finalizes any durable state.

## Decision

Implement one internal and inert current-discovery invocation for one active account.
The invocation reconciles durable staging before any provider request, validates the lifecycle, cursor, and credential, decrypts the refresh token only in memory, and repeats the lifecycle read before provider contact.
It makes exactly one OAuth refresh exchange and never retries that exchange.

Use the existing exact `golang.org/x/oauth2 v0.36.0` root package with `AuthStyleInParams` for the refresh request.
Create one expired token containing only the decrypted refresh token, construct one token source, and call `Token` exactly once through an InboxGate-owned HTTP client.
This decision narrows ADR 0008's prohibition on `TokenSource` to permit this one explicit call.
Automatic API-call refresh, `oauth2.NewClient`, retrying token sources, provider discovery, generated Google clients, and application-default credentials remain prohibited.

Prevalidate the complete bounded refresh response before the dependency decodes it.
Require a duplicate-free JSON object with byte-exact case-sensitive field names, exact bearer token type, canonical positive expiry no greater than 86,400 seconds, a bounded access token, and either no scope or exactly the two enrollment scopes.
Reject invalid raw UTF-8 and unpaired UTF-16 surrogate escapes before any provider field can be classified, normalized, discarded, or trusted.
Reject refresh-token rotation because this slice has no durable rotation protocol.
Map only exact HTTP 400 `invalid_grant` and `admin_policy_enforced` responses to the existing lifecycle reasons.
Every other refresh failure preserves the active lifecycle, durable credential, and cursor.

Read Gmail history only through the fixed `users.history.list` endpoint with `userId=me`, the fresh durable cursor, `historyTypes=messageAdded`, a validated page size, and one fixed partial-response selector.
Accept no more than ten pages, 500 history records and 500 additions per page, 5,000 unique message identities, or 4,096 bytes per opaque page token.
Reject token cycles, conflicting message and thread identities, nonincreasing history records, malformed projected responses, and any incomplete page chain.
The final page history ID is the only proposed next cursor.

Treat a history endpoint HTTP 404 as a fixed stale-history result.
Do not change lifecycle state, reset the cursor, call a full-sync endpoint, or create staging.
Persisted stale status and bounded full reconciliation remain required in a later synchronization-status or backfill slice.

Fetch each unique message at most once apart from the bounded retry policy.
Use `format=FULL` with one deterministic finite fields selector that includes only identifiers, labels, internal date, size estimate, selected top-level header names and values, filenames, attachment IDs, and nested MIME structure.
Generate exactly 32 supported nested part levels plus an overflow sentinel.
Reject more than 1,000 returned part nodes or any deeper structure.
Never request attachment content.

Retain only the ten gate-header names approved by issue #32.
Treat all headers, labels, filenames, attachment IDs, identifiers, and MIME structure as untrusted data.
Use standard-library MIME-word and mailbox parsing, discard malformed optional syntax conservatively, and pass every complete record through `mail.Normalize`.
Do not retain an arbitrary header map, filename, attachment ID, raw response, or provider diagnostic.

Treat an exact message endpoint HTTP 404 as a vanished message.
Omit that message from the aggregate, increment only the bounded internal vanished count, and allow the complete final cursor to advance.
Keep history 404 and message 404 as distinct outcomes.

After the one refresh, map an exact Gmail HTTP 401 only to `gmail_unauthorized_after_refresh`.
Map a Gmail HTTP 403 only to `gmail_domain_policy` when one bounded duplicate-free error object contains that one canonical reason and no conflicting reason.
Persist trusted reauthorization transitions with an independent bounded context and stop all later Gmail and storage work.

Retry history and message GETs only for transport failures, exact rate-limit reasons, HTTP 429, or HTTP 500, 502, 503, and 504.
Transport failure includes failure before response headers, failure while reading the bounded response body, and failure while closing that body.
Each such failure consumes one explicit attempt and the next one-two-four-second scheduled wait while the caller context remains active.
An oversized or syntactically invalid completed response remains non-retryable.
Permit one initial attempt and three retries with one, two, and four second bases, cryptographic jitter from zero through 250 milliseconds, and a canonical numeric `Retry-After` value no greater than 30 seconds.
Each attempt has its own 15-second deadline and preserves shorter caller cancellation.
Use a fresh nonpersistent HTTP/1 connection for each explicit Gmail attempt so `net/http` cannot transparently retry a reused HTTP/1 connection or an HTTP/2 stream beneath the bounded scheduler.
No goroutine, parallel message fetch, batch request, redirect, mutable request target, hidden transport retry, or connection reuse is permitted.

Call `CommitCurrentDiscovery` exactly once only after the complete page chain and every non-vanished message have succeeded.
Do not call cursor-only `CommitSynchronization`.
Do not replay an uncertain storage outcome or make another provider request in the same invocation.
A later explicit invocation begins with durable reconciliation.

## Alternatives considered

Using `METADATA` format would omit MIME attachment structure and could not truthfully build the existing canonical record.
Using unrestricted `FULL` format would retrieve sensitive body content that this phase neither needs nor may persist.
The finite partial-response selector obtains only structural metadata and includes an explicit depth-overflow sentinel.

Calling `messages.list` after a stale cursor would silently introduce a full-sync algorithm, additional pagination, selection, durability, and restart requirements.
This slice instead returns a fixed stale-history category and leaves the durable cursor unchanged.

Refreshing automatically through an OAuth HTTP client could perform an unbounded or repeated credential exchange during Gmail retries.
The selected one-call token source separates the single credential exchange from every Gmail request.

Committing each history page would leave the cursor ahead of messages from a later failed page.
Holding the complete bounded chain in memory and using one existing aggregate preserves cursor transactionality.

Parallel or batch message reads could reduce latency but would complicate cancellation, request accounting, provider classification, and deterministic bounds.
This slice stays sequential.

## Dependency and supply-chain review

No dependency is added or changed.
The implementation uses the Go standard library, the existing exact `golang.org/x/oauth2 v0.36.0` root package accepted by ADR 0008, `internal/cryptobox`, `internal/account` lifecycle vocabulary, and the repository-owned storage interface.
The complete module graph, checksum file, notices, workflow pins, container inputs, and capability registry remain unchanged.
Removal deletes the inert current-discovery caller and its tests after downstream callers are removed while leaving append-only migrations and durable canonical data intact.

## Security and privacy impact

This decision adds the first outbound Gmail history and message-read boundary and an explicit refresh-token use boundary.
Refresh tokens, client secrets, access tokens, account identities, cursors, Gmail identifiers, thread identifiers, labels, headers, filenames, attachment IDs, and normalized metadata are sensitive.
Repository-owned mutable token buffers are cleared after use where practical without claiming complete Go process-memory zeroization.
Tokens never enter a URL, query, cookie, error, log, result, fixture description, or durable access-token store.

The Gmail surface contains only bodyless fixed-authority GET requests.
It adds no Gmail mutation method, message body, attachment request, raw MIME request, arbitrary field mask, provider passthrough, URL fetch, SQL, shell, HTTP server, CLI, MCP, scheduler, or runtime capability.
The selected header and MIME metadata remain data only and cannot authorize suppression, urgency, provider mutation, tool use, policy changes, or credential disclosure.

An active account can race with a concurrent pause or lifecycle transition after the final preflight read.
The bounded read-only provider requests may complete, but the storage finalization guard prevents canonical promotion or cursor advancement unless the lifecycle remains active.
This residual race is accepted for the inert slice and is recorded in the threat model.

This orchestration reaches storage operations affected by `TURSO-001` through `TURSO-005` without adding SQL.
All five risks remain open.
The current work stays credential-free and literal-loopback, maps storage failures to fixed categories, reconciles before provider work, performs one aggregate commit without replay, and preserves existing accepted row and value bounds.
It does not prove cross-authority control, diagnostic containment inside the driver, bounded close cancellation, redirect control, pre-allocation response limits, or Turso Database engine behavior.
Remote Turso execution and live Gmail synchronization remain prohibited until a later activation decision supplies the missing engine and transport evidence.

## Rollback and removal

No pre-existing file is deleted, renamed, truncated, or replaced.
Migrations `0001` through `0005` remain byte-for-byte unchanged.
Rollback removes the internal caller from use while leaving durable ciphertext, canonical messages, current-discovery staging, and append-only migrations intact.
Only the repository owner may authorize a destructive schema downgrade or file removal.

## Consequences

Credential-free callers can exercise one deterministic current Gmail discovery path against synthetic providers and fake or literal-loopback storage.
Complete page chains can produce canonical metadata and advance one cursor through the existing atomic aggregate.
Transient failures, hostile responses, bounded backlog, stale history, trusted authorization failures, vanished messages, cancellation, and uncertain storage outcomes have distinct fixed behavior.

The use case remains unavailable to operators and the running service.
`gmail.read` and `gmail.current_sync` remain not implemented and impossible to enable because no executable caller exists.
Live Google authorization, Gmail access, remote Turso use, secret injection, deployment, and production migration remain deferred to separately approved owner gates.

## Validation

The preserved tests-only red commit must predate this decision and all production implementation.
Tests cover exact refresh form and response validation, lifecycle classification, fixed Gmail request inventory, pagination and identity bounds, stale history, finite MIME projection, hostile header normalization, vanished messages, retry timing and cancellation, the 20,041 absolute attempt cap, one aggregate commit, no cursor-only mutation, uncertain-outcome restart behavior, bounded results, and credential-free fake-storage end-to-end flow.
Repeated focused tests, race tests, storage and migration tests, `make check`, diff validation, migration checksums, dependency and capability inventories, and all CGO-disabled release-target builds must pass before merge.
