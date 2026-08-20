# InboxGate threat model

Status: accepted bounded MCP candidate inspection with known upstream risks for issue #44.

## Security objectives

- Preserve the confidentiality of provider credentials, email metadata, message excerpts, account policy, and review decisions.
- Prevent InboxGate, Hermes, or untrusted email content from mutating Gmail state.
- Expose only bounded, authenticated operations required by the declared capability surface.
- Keep synchronization and review state correct across retries, duplicates, crashes, and restarts.
- Produce useful audit evidence without logging secrets or private message content.

## Assets

The highest-value assets are Google OAuth credentials, encryption keys, account identities, synchronization cursors, stored email metadata and excerpts, review decisions, MCP credentials, configuration policy, and audit records.

## Trust boundaries

| Boundary | Untrusted input | Required control |
| --- | --- | --- |
| Operator to CLI and configuration | Arguments, paths, YAML, environment names, capability policy | Strict parsing, bounded input, structural secret avoidance, path omission, deterministic output, fail-closed capability validation |
| Browser to one-shot OAuth callback | Authorization code, denial, state, request target | Exact route and method, one-time ten-minute state, constant-time comparison, PKCE S256, strict query shape, bounded request target, no-store fixed response, capacity-one result |
| InboxGate to Google OAuth, OpenID Connect, and Gmail profile | Client credentials, code, verifier, bearer token, subject, email, history ID, provider responses | Fixed endpoints, exact read-only scopes, owned redirect-rejecting client, 15-second deadlines, 16 KiB body limits, no retry, strict decoding, fixed diagnostics, discard-only email |
| InboxGate to Google OAuth revocation | Refresh token, provider status, redirects, response body, transport failure | Proven durable revoked-attempting claim, fixed HTTPS authority, body-only form token, owned proxy-disabled TLS transport, redirect rejection, at most one request, no retry after ambiguous completion, 15-second deadline, 16 KiB response limit, fixed diagnostics, exact local ciphertext deletion |
| InboxGate to Google OAuth refresh and Gmail discovery | Refresh token, client secret, access token, HTTP status, retry headers, history pages, message metadata, MIME structure, history cursors | One fixed refresh POST, fixed read-only Gmail GETs, proxy-disabled TLS transport, redirect rejection, per-request deadlines, pre-decode body limits, duplicate-aware strict decoding, finite field projection, bounded retries and pagination, fixed diagnostics, transactional cursor advancement |
| Email sender to InboxGate | Headers, HTML, text, links, instructions | Treat all content as data, sanitize HTML, truncate content, mark untrusted content |
| InboxGate to Turso adapter | URL, redirects, protocol scheme and authority, responses, query results, account identities, synchronization cursors, ciphertext credentials, lifecycle values, canonical metadata, gate decisions, uncertain transport outcomes | Repository-owned typed interface, separate URL and token values, verified HTTPS for the initial remote endpoint only, credential-free literal-loopback migration and typed persistence execution only, fixed outer diagnostics, bounded context-aware requests, fixed parameterized product-state SQL, durable uniqueness, typed compare-and-swap, one atomic current-discovery aggregate, separate-connection visibility, no automatic mutation replay, fresh-run reconciliation, and explicit accepted-risk tracking for driver-controlled authority, redirect, response buffering, and close behavior |
| Hermes to MCP | Authentication, tool inputs, pagination | Authentication, explicit schemas, bounds, allowlisted capabilities, audit events |
| Runtime to logs and health endpoints | Errors, state, identifiers | Redaction, minimal readiness detail, private binding, no credentials or message bodies |
| Owner to release workflow | Version, expected commit, dispatch identity, immutable-release setting | Exact input syntax, owner-only manual dispatch, immediate manual settings check, current-main and successful-CI gates |
| Release runner to GitHub | Automatic token, OIDC identity, drafts, assets, attestations | Narrow permissions, immutable Action pins, disabled checkout credentials, remote byte verification |
| Release artifacts to consumers | Binaries, archives, SBOM, checksums, generated notes | Reproducible builds, normalized archives, SPDX validation, checksums, provenance, immutable publication |

## Primary threats and controls

### Credential disclosure

Secrets could leak through committed files, examples, logs, errors, process arguments, or MCP responses.
Configuration may name secret-bearing environment variables but may not contain their values.
Tests use synthetic values, provider credentials are stored with versioned authenticated encryption, and all operator-visible output is redacted.

Configuration schema v1 accepts environment-variable names only in fields ending in `_env`.
The validation path checks the name grammar but never looks up the named value, never substitutes environment data into YAML, and never reports a rejected scalar or list value.
The effective inspection path prints validated environment-variable names as policy but never acquires, checks, hashes, measures, or represents their named values.
Its only environment lookup selects the configuration path through `INBOXGATE_CONFIG`.

### Effective policy disclosure and side channels

Successful `config effective` stdout can contain sensitive non-secret policy, including sender domains, subject terms, bind addresses, schedules, retention choices, and environment-variable names.
Operators are warned to review the output before putting it in public issues, logs, or chat systems.
The selected path is not emitted, so the output does not reveal usernames, home directories, mount details, or other host path data.
Provenance reveals only the path-selection class and whether each field came from the file or compiled defaults.
The output contains no timestamps, process identifiers, hostnames, secret presence, service availability, or runtime state.
Invalid configuration produces no partial normalized output, and write failures use a generic diagnostic.
Existing file, YAML node, depth, list, string, and schema limits continue to bound rendering.
The command has no network client, filesystem-write path, provider activation, database activation, or MCP exposure.

### Capability inspection and authority confusion

Configuration policy could appear to grant behavior that the binary does not implement, or an invented capability name could be mistaken for supported authority.
The typed registry separates compile-time implementation status, validated configuration status, and derived enablement.
Unknown names fail closed, true values for not-implemented configurable capabilities fail validation, and a not-implemented entry can never be enabled.
Gmail mutation is always prohibited and cannot be configured.
Zoho and direct Vikunja behavior remain visible as excluded entries but cannot be configured or activated.

The local `capabilities` command loads and validates inert policy only.
It does not start a service, check credential presence, contact a provider or database, expose MCP, or grant runtime authority.
The selected configuration path and its source class are omitted.
Output contains no timestamps, hostnames, process identifiers, service health, connectivity, migration state, account state, or secret presence.

Required secret names can reveal operational naming conventions.
They are validated environment-variable names only and are sorted before serialization.
The command never reads, substitutes, hashes, measures, or derives information from the named values.
Operators are warned to review capability output before sharing it publicly.

### Process-health listener and runtime logs

The process-health runtime introduces the first inbound network listener and operational log stream.
The listener always registers exact liveness and process-readiness paths with fixed bounded JSON documents.
It conditionally registers only the authenticated MCP route described below and has no Gmail, OAuth, scheduler, provider, mutation, URL-fetching, SQL, shell, or static-content route.
The operator gate can add one bounded typed database read source to that route only for credential-free literal-loopback storage.
Configuration validation and runtime construction reserve both health paths against MCP overlap whether MCP is enabled or disabled.
Unknown paths, unsupported methods, and request bodies receive fixed errors that never echo request data.
Percent-encoded alternate spellings of a health path remain unmatched and are logged only as the bounded `unmatched` operation.
Configured timeouts, a compiled 16 KiB header limit, a compiled limit of 128 concurrently accepted connections, and the configured request-body bound constrain the standard-library server.
The listener acquires admission before the underlying accept, blocks further application acceptance until a permit is released exactly once by connection close, and unblocks permit waiters during shutdown.

The health routes are unauthenticated because schema v1 has no separate probe credential and the MCP bearer token belongs to another trust boundary.
They reveal only `live`, `ready`, or `not_ready` and must bind only to an approved private interface or private reverse-proxy path.
The default all-interface listener is not authorization for public exposure.
Detailed database, migration, scheduler, account, provider, secret, or connectivity diagnostics remain absent.

Structured lifecycle and request logs use only bounded event names, allowlisted operations and methods, numeric status and duration, bounded outcomes, and bounded failure reasons.
The implementation omits raw errors and suppresses the standard-library server error logger so request data and listener addresses cannot bypass the allowlist.
It never logs raw paths, queries, hosts, remote addresses, headers, bodies, user agents, configuration paths, listener addresses, YAML-named environment variables, secret presence, account identifiers, provider data, or message data.

Readiness becomes false before graceful shutdown begins.
The first termination signal starts one compiled 10-second deadline before MCP Close and HTTP draining, and MCP cancellation and the server shutdown share it.
A second signal cannot restart or extend that deadline, and an expired deadline forces the server closed with a bounded failure record.
The local `doctor` command constructs the runtime without binding a socket, reading YAML-named environment values, or activating a provider.

### Authenticated MCP capability boundary

The enabled MCP route is the first authenticated application endpoint and creates an inbound authentication, protocol-parser, SDK, and capability-disclosure boundary from the approved Hermes service identity to InboxGate.
The route is absent and its selected environment variable is not read when `mcp.enabled` is false.
Enabled `serve` resolves the environment variable named by `mcp.bearer_token_env`, requires a canonical unpadded base64url encoding of exactly 32 bytes, and fails before bind through one fixed diagnostic when construction fails.
When operator tools are enabled, it then resolves only the selected database URL and optional token names, requires a credential-free literal IPv4 or IPv6 loopback HTTP endpoint, and constructs no source when either gate is disabled.
The repository clears its temporary encoded byte slice and the handler-owned decoded token on close where practical, but Go strings, compiler copies, garbage-collected memory, and the process environment prevent a complete zeroization guarantee.

The bearer token authenticates one approved Hermes service identity and does not provide per-account or per-tool authorization.
It is replayable until both copies are rotated, so an approved private network path, TLS with hostname verification, firewall and proxy policy, secret storage, bounded rotation, and incident response remain mandatory before deployment.
Host validation prevents malformed or ambiguous HTTP authorities but does not authorize a hostname or replace DNS, TLS, proxy, or private-routing policy.
Forwarded headers, client address, user agent, client information, and Host never influence authorization, routing decisions, response identity, or audit identity.

The outer wrapper rejects every Origin, CORS request header, and browser fetch-metadata header before protocol decoding.
It accepts POST only on the exact escaped configured path, rejects queries and aliases, requires exact JSON media and JSON acceptance, and emits no CORS response headers.
These controls reduce browser credential abuse and DNS-rebinding ambiguity but do not make public exposure safe.
The deployment boundary must reject unapproved hostnames and routes before traffic reaches InboxGate.

The wrapper requires exact protocol revision `2026-07-28` in both the routing header and self-describing request metadata.
It rejects legacy initialization, initialized notifications, session identifiers, event identifiers, SSE, resumability, older revisions, conflicting method or tool routing, unexpected named components, and every method outside discovery, tools/list, and tools/call for the three compiled tool names.
The official Go SDK v1.7.0 remains inside this wrapper and cannot independently broaden the exposed authority.
Tests start isolated processes with each of the eleven documented `MCPGODEBUG` compatibility parameters and all parameters together to prove that sessions, legacy behavior, weak media handling, Origin acceptance, broader methods, broader tools, and unbounded bodies remain unavailable.

The wrapper authenticates before reading or decoding a body and uses constant-time comparison over decoded fixed-length token bytes.
Missing, malformed, duplicated, joined, padded, case-variant, whitespace-variant, and incorrect credentials receive the same fixed response.
The token, Authorization header, environment-variable name, secret presence, length, prefix, suffix, hash, fingerprint, and decoded bytes never enter output or audit fields.

Request exhaustion is bounded by the smaller of the configured body limit and 65,536 bytes, JSON container depth 16, decoded node count 2,048, one object rather than a batch, 16 concurrent admitted requests, and a five-second application deadline.
The seventeenth request fails immediately without an unbounded queue.
The application deadline, client cancellation, and shutdown cancellation close active request bodies and reach application work.
Complete SDK and InboxGate-owned JSON-RPC responses are buffered and rejected before commitment when they exceed 65,536 bytes, including errors that contain expandable valid request IDs.
The server's existing header, connection, timeout, and graceful-shutdown bounds remain additional controls.

The repository parser independently rejects invalid UTF-8, duplicate fields, NUL aliases, case aliases, trailing values, unsupported client capabilities, extra arguments, and header-body routing differences.
Authenticated JSON-RPC errors use fixed categories without a data field, decoder text, SDK diagnostics, request fragments, or reflected values.
The SDK is still a supply-chain and parser risk, so the exact v1.7.0 module and full resolved graph are pinned, licensed in third-party notices, checked against published advisories, included in release build metadata and each canonical SBOM binary-location inventory, and covered by an accepted removal plan in ADR 0014.

The always-registered tool is `system_capabilities` with an empty closed input schema and read-only, idempotent, non-destructive, closed-world annotations.
It adapts the typed capability registry and cannot reach Gmail, OAuth, Turso, storage, review, backfill, shell, SQL, URL fetching, Vikunja, provider connectivity, or arbitrary JSON-RPC behavior.
Its result can reveal compiled capability names and validated secret environment-variable names, which are operational metadata and must remain authenticated and reviewed before sharing.
It never inspects or reveals secret values or presence, account state, database state, migration state, provider state, hostname, time, or process state.

When both MCP and operator tools are enabled, the same one-principal bearer authorizes tenant-wide `accounts_list` and `mail_sync_status` reads for every enrolled account.
Neither tool accepts arguments, selectors, pagination, roles, tenants, or account filters, and both use the same closed annotations and complete response bound.
Authentication and structural validation finish before exactly one `ListAccounts` call, while disabled, unauthorized, malformed, and unknown requests make no storage call.
The application service receives only that narrow read interface and an authority-free snapshot model, so MCP cannot reach a storage handle, SQL, mutation, Gmail, OAuth, provider, synchronization, or backfill executor.
Rows are limited to 100 and must contain sorted unique opaque identifiers, fixed Gmail provider values, and valid lifecycle shapes.
The account-list result excludes provider subjects, display names, addresses, credential and cursor presence, cursor values, endpoints, and secrets.
The synchronization result discloses only initialized or uninitialized cursor status and uses explicit unavailable, not-persisted, and null values for facts that are not durable.
Every source, decoding, deadline, cancellation, or size failure becomes fixed JSON-RPC `-32603` without partial output or upstream diagnostics.
The fixed audits use `mcp.accounts_list` or `mcp.mail_sync_status` and contain no account data.
This tenant-wide authorization is valid only for the single owner-approved Hermes principal and must be replaced before multiple principals, tenants, delegation, or roles are introduced.

Each request emits exactly one bounded structured audit event at every valid configured log level containing only a fixed operation, method class, numeric status, bounded duration, and outcome.
JSON-RPC semantic failures retain a failure outcome independently of their HTTP `200` transport status.
Audit output excludes body, response, arguments, protocol metadata, client identity, capabilities, headers, Host, path, query, address, user agent, token state, secret names, and SDK errors.
The current audit stream is not durable, so approved retention and operational collection remain a deployment prerequisite and must be revisited before sensitive mail tools are added.

### Malicious or mistaken configuration

An operator-provided YAML file could exploit parser complexity, hide a duplicate or misspelled limit, target a non-file object, or place secret data in a name-only field.
Validation opens the requested target and requires the resolved object to be a regular file, so a symlink to a regular file is permitted while directories, devices, sockets, and FIFOs are rejected.
The reader consumes at most 65,537 bytes and rejects content above 65,536 bytes.
Before typed decoding, the parser requires one UTF-8 mapping document and rejects document-end markers, directives, anchors, aliases, merge keys, custom tags, nulls, non-string keys, duplicate keys, unknown keys, decoded scalar controls, and noncanonical scalar forms.
Mappings and sequences are limited to depth 8 and the YAML tree is limited to 4,096 nodes.
Typed validation then applies explicit field bounds and cross-field relationships in stable field-path order.
Diagnostics contain locations and generic reasons but no rejected scalar value, list content, file content, or named environment-variable value.
The parser has no network client, arbitrary unmarshalling hook, include, template, substitution, capability activation, or filesystem-write path.
The release command embeds the Go standard library timezone database so IANA validation remains available without a host zoneinfo installation or another dependency.

### Excess Gmail authority

An overbroad OAuth scope or a generic Gmail proxy could permit destructive mailbox actions.
The application requests read-only Gmail access and implements only handwritten calls required for discovery and retrieval.
No tool or command may send, delete, archive, label, forward, or mark a message as read.

The one-shot enrollment command requests `openid` only for stable subject identity and `gmail.readonly` as its only Gmail data scope.
It performs one token exchange, one UserInfo read, and one `users/me/profile` read and has no message or mutation request surface.
State replay, callback CSRF, authorization-code interception, PKCE substitution, scope expansion, partial grants, redirects, malicious provider bodies, and concurrent enrollment fail closed through the bounded contracts recorded in ADR 0008.
Plaintext credentials remain memory-only and repository-owned mutable buffers are cleared where practical without claiming complete Go memory zeroization.
Cursor-first staged persistence makes account-only and cursor-only states restartable, rejects credential-only state as recovery-required, and never claims atomicity across three durable records.

### Bounded current Gmail discovery

The internal current-discovery prerequisite adds the first refresh-token use and Gmail history and message-read boundary outside enrollment.
It reconciles durable current-discovery staging before provider work, requires an exact active lifecycle with one remaining transition version, reads the exact cursor and ciphertext, authenticates decryption, and repeats the lifecycle read before the one refresh exchange.
Paused, reauthorization-required, revoked, incomplete, malformed, version-exhausted, or concurrently changed accounts make no provider request.

The refresh exchange uses the fixed Google token authority, form-body client authentication, one expired token containing only the decrypted refresh token, and exactly one call to the existing OAuth token source.
An InboxGate-owned wrapper rejects redirects, wrong request shape, oversized or unsupported responses, duplicate JSON fields, noncanonical expiry, scope drift, refresh-token rotation, and unknown response fields before dependency decoding.
Every allowed OAuth, Gmail, and Google error field name is matched byte-for-byte with case-sensitive nested allowlists.
Raw invalid UTF-8 and unpaired UTF-16 surrogate escapes fail before a repaired replacement character could enter identity, classification, normalization, or discard logic.
The refresh request is never retried, the access token is never persisted, and repository-owned mutable token buffers are cleared after use where practical.
Only exact HTTP 400 `invalid_grant` and `admin_policy_enforced` objects can enter their existing lifecycle transitions.

Every Gmail request is one bodyless GET to a fixed `users.history.list` or escaped `users.messages.get` path.
The access token appears only in the authorization header.
History requests fix `historyTypes=messageAdded`, the caller-validated page size, and one narrow projection.
Message requests fix `format=FULL` and one finite projection that excludes snippets, raw MIME, message body data, body sizes, attachment bytes, classification values, and links.
There is no Gmail mutation method, message-body request, attachment call, arbitrary field mask, provider passthrough, URL fetch, generated client, batch request, or parallel per-message work.

The history chain accepts at most ten pages, 500 records and 500 additions per page, 5,000 unique message identities, and 4,096 bytes per opaque page token.
It rejects token cycles, nonincreasing record IDs, conflicting message-thread identity, incomplete page chains, malformed projected fields, and any final cursor regression.
An exact history endpoint 404 is a fixed stale-history outcome that does not mark reauthorization, reset the cursor, request full synchronization, create staging, or mutate durable state.
Durable stale status and bounded full reconciliation remain required before release.

Each message response is limited to 262,144 bytes and accepts at most 256 top-level header entries, 65,536 selected-header bytes, 1,000 MIME part nodes, and 32 nested part levels with an explicit overflow sentinel.
Only ten case-insensitive header names survive decoding.
Standard-library encoded-word and address parsers turn malformed optional syntax into absent conservative signals.
Filenames and attachment IDs contribute only to a bounded metadata count and are discarded before normalization.
An exact message endpoint 404 is counted as vanished and omitted while the complete history cursor may still advance.

An exact Gmail 401 after the one refresh can enter only `gmail_unauthorized_after_refresh`.
A Gmail 403 can enter only `gmail_domain_policy` when one bounded duplicate-free error object contains that single canonical reason without conflict.
Trusted transitions use an independent 15-second cleanup context and stop all later Gmail and storage work.
Other provider failures retain the active lifecycle and do not move the cursor.

History and message GETs permit one initial attempt and three retries only for transport failures, exact rate-limit reasons, HTTP 429, and HTTP 500, 502, 503, or 504.
Failures before headers, during the bounded body read, or during body close each consume one explicit attempt and scheduled wait while caller authority remains active.
Completed oversized or malformed responses remain non-retryable.
The one, two, and four second bases include at most 250 milliseconds of cryptographic jitter, while only a canonical numeric `Retry-After` from one through 30 seconds can lengthen a wait.
Caller cancellation stops a request or sleep.
Each explicit Gmail attempt uses a fresh nonpersistent HTTP/1 connection, which prevents the standard transport from silently retrying a stale reused HTTP/1 connection or an HTTP/2 stream outside the scheduler.
The absolute invocation limit is 20,041 provider request attempts and no storage failure can trigger another Gmail request in the same invocation.

The complete page chain and every normalized non-vanished message must succeed before one `CommitCurrentDiscovery` call.
The use case never calls cursor-only initialization.
A storage conflict or uncertain response returns a fixed category without replay, and a fresh invocation begins with reconciliation.
An account can race with a concurrent pause or lifecycle transition after the final preflight, so bounded read-only provider calls may finish after the state changes.
The existing finalization trigger still prevents message promotion and cursor advancement unless the lifecycle remains active.

All email-derived identifiers, headers, labels, dates, sizes, filenames, attachment identifiers, and MIME structure are untrusted data.
They cannot authorize suppression, urgency, a tool call, a provider mutation, SQL, a policy change, or credential disclosure.
The internal result contains only bounded counts and a cursor-advanced flag and exposes no provider value.
The use case remains disconnected from commands, scheduling, service startup, HTTP, health, capabilities, MCP, remote Turso, and live credentials.

### Prompt injection through email

Email is attacker-controlled content that may contain instructions aimed at Hermes or an operator.
The deterministic gate never executes content.
Candidate output must explicitly mark content as untrusted, apply MIME and HTML handling, and enforce size limits before Hermes receives it.

### Confused deputy and capability expansion

An authenticated caller could use a broad interface to access accounts or operations beyond its intended authority.
MCP tools use typed, narrow schemas, bounded results, opaque identifiers, allowlisted capabilities, and account-aware authorization.
InboxGate does not expose raw SQL, arbitrary Gmail calls, shell commands, URL fetching, or direct Vikunja calls.

### State corruption and replay

Retries, duplicate Gmail history, concurrent work, or a crash could skip mail or repeat review changes.
Durable writes and cursor movement must be transactional.
External and review operations require stable idempotency keys, valid state transitions, bounded retries, and restart tests.

### Atomic current-discovery staging

Normalized Gmail identifiers, addresses, subjects, selected headers, labels, hashes, cursors, attempts, and staging rows are sensitive attacker-controlled data.
They remain data only and never become instructions, SQL text, diagnostics, logs, health output, configuration output, capability output, or a public read surface.
The current slice stores no body, snippet, raw MIME, attachment bytes, link target, OAuth value, credential, raw provider JSON, or arbitrary header map.

The storage boundary validates and canonicalizes every message before deriving full domain-separated SHA-256 record, attempt, and manifest identifiers.
The aggregate is limited to 5,000 unique messages and 16,777,216 bytes of canonical length-prefixed encoding.
Each staging statement is fixed parameterized SQL with 64 slots and exactly 514 arguments, including inert padding that cannot create a row.
One account can have only one bounded open or sealed attempt.
The fixed insert reconstructs an exact hexadecimal `row_witness` from every live staging field, and schema triggers reject every staging update.
The immutable `manifest_witness` binds the manifest domain, message count, and every ordinal-ordered row witness.

Before finalization, the adapter decodes and re-encodes canonical metadata, verifies the metadata SHA-256, and verifies the record ID derived from the account and Gmail message IDs.
Finalization is one fixed insert into a write-only view whose trigger verifies the sealed manifest witness, active lifecycle, exact current cursor, stable thread identity, key collisions, row count, ordinal sequence, encoded byte total, every schema-reconstructed row witness, and the complete ordinal-ordered manifest witness.
The schema prevents sealed attempt insertion, mutation of attempt commitments, and every staging update.
SQLite does not recompute SHA-256-derived identities, so arbitrary raw-SQL authority could still create a completely self-consistent forged attempt and witness.
InboxGate exposes no raw-SQL surface and keeps remote activation gated on exact engine behavior.
Canonical message promotion, bounded mutable metadata updates, cursor advancement, and staging cleanup succeed or roll back together.
Pause and reauthorization-required block finalization and retain bounded staging.
Revocation removes only noncanonical staging in the lifecycle statement and preserves canonical messages.

The manifest witness is bounded at 33,554,510 bytes, and the row witnesses can add another 33,554,432 bytes of hexadecimal text per maximum attempt before live staging fields and database overhead.
Remote activation therefore requires exact engine evidence for ordered witness reconstruction, trigger rollback, parameter limits, allocation behavior, writer serialization, and concurrency under this bounded storage amplification.

Every mutation is attempted once per invocation and is followed by exact separate-connection visibility while the mutation connection remains reserved.
Unproven sessions are discarded and never replayed in the same invocation.
A fresh explicit reconciliation may finalize a valid sealed attempt or abort a well-formed open attempt with an unchanged cursor without contacting Gmail.
Malformed, oversized, mixed, or cursor-divergent state fails closed for recovery.

The literal-loopback exact-driver model does not execute SQLite or the Turso Database engine.
It therefore cannot prove the remote engine's 514-parameter limit, strict-table behavior, trigger execution, constraint rollback, writer serialization, or concurrent finalization.
Remote execution remains prohibited until later approved evidence proves those properties without exposing credentials or sensitive stored data.

### Deterministic gate persistence

Sender addresses, recipients, subjects, labels, selected headers, canonical metadata hashes, gate outcomes, reason codes, and evaluation timestamps are sensitive untrusted or derived data.
The pure gate imports no storage, network, runtime, provider, MCP, shell, URL-fetching, or capability authority.
It applies one fixed precedence, parsed-mailbox final-`@` boundary-aware ASCII domain matching, literal Unicode case folding without normalization or regular expressions, and a closed sorted reason vocabulary.
Candidate-term and urgent-term lists reject Unicode case-fold-equivalent duplicates through the same bounded canonical fold used for matching.
Literal matching performs at most 512 searches over one canonical simple-fold subject bounded at 16,384 bytes with each folded term bounded at 512 bytes.
Missing optional metadata is absence and cannot create an owner allow, candidate, urgency, or direct-recipient signal.

The input hash binds gate version 1, the canonical message metadata hash, both gate booleans, and all six byte-sorted policy lists with domain separation and explicit length framing.
The durable row contains only the canonical record ID, version, source metadata hash, input hash, closed outcome, canonical bounded reason JSON, and bounded evaluation timestamp.
It contains no free-form explanation, policy value, address, subject, label, body, snippet, raw MIME, attachment, credential, provider response, or arbitrary header map.

Migration `0006_gate_decisions.sql` adds one strict binary-keyed table with a restrictive foreign key to canonical messages.
The fake and Turso implementations reject malformed rows, stale source metadata, blind replacement, wrong expected revisions, and the same input identity with different semantics.
The Turso adapter uses one fixed lookup and one fixed parameterized compare-and-swap mutation, attempts the mutation once, proves exact durable state through a separate physical connection, discards an unproven session, and performs no same-invocation replay.
The evaluator reads durable state before the clock, fresh-reads after a reported commit success, returns a concurrent idempotent winner's durable timestamp, and requires an exact prior revision for policy or metadata replacement.

The classifier and evaluator remain unreachable from every executable runtime path.
Credential-free literal-loopback tests model exact driver SQL and transport behavior but do not prove remote Turso Database constraint, foreign-key, writer-serialization, or visibility semantics.
Remote migration `0006` and live gate-decision storage remain prohibited pending later approved evidence.

### Bounded candidate content

Message body bytes, MIME structure, charset declarations, HTML, canonical excerpts, content hashes, and fetch timestamps are sensitive untrusted email data.
They are never instructions and cannot authorize a Gmail mutation, provider request, database operation, MCP tool, configuration change, secret disclosure, SQL statement, shell command, or URL fetch.
The extractor is internal and inert, and no command, scheduler, service, HTTP route, health handler, capability, or MCP tool can invoke it.

Eligibility requires an active lifecycle, current canonical message, and current persisted `review_candidate` or `urgent_review_candidate` decision before the provider credential is read.
One accepted OAuth refresh is followed by exact lifecycle, message, and gate re-reads before the Gmail content GET.
A later authority or eligibility race may allow that bounded read-only GET to finish, but the storage mutation joins the exact active lifecycle version, canonical message identity, metadata hash, gate revision, candidate outcome, and source-bound next value.
No excerpt becomes current after those joined conditions change.

The Gmail request uses only `users.messages.get`, a bodyless GET, `format=FULL`, an escaped message ID, and a finite selector for identity and MIME fields.
It excludes snippets, raw MIME, arbitrary provider operations, mutations, and attachment retrieval.
A Gmail API limitation prevents `format=FULL` field selection from filtering the repeated headers array by name, so arbitrary header names and values can exist ephemerally within the 1 MiB response cap.
The decoder validates the bounded header structure, consumes only Content-Type and Content-Disposition, and discards all other headers before any typed boundary, persistence, log, diagnostic, or result.
A filename-bearing, attachment-backed, or attachment-disposition node excludes its complete descendant subtree from selection.
The response is limited to 1 MiB, selected decoded bytes to 512 KiB, MIME nodes to 1,000, MIME depth to 32, attempts to four, and each attempt to 15 seconds.

The complete tree walk prefers one eligible inline plain-text part and falls back to one eligible inline HTML part only when no plain part exists.
Canonical unpadded base64url, exact size agreement, eligible-text-only charset interpretation, and a closed charset set prevent decoder ambiguity without giving excluded MIME parameters availability authority.
One bounded closed Content-Disposition decision per node prevents a small inline data field or descendant from bypassing provider attachment semantics.
The repository-owned HTML state machine rejects malformed or ambiguous markup, permits self-closing syntax only for closed void elements, removes active and hidden subtrees, requires closed entity decoding before evaluating security-sensitive visibility attributes, handles exact hidden `!important` and numeric-zero forms, rejects ambiguous computed or obfuscated visibility values, emits text only, and never emits attributes, links, URLs, images, CSS, forms, scripts, event handlers, or markup.
The canonicalizer normalizes line endings, replaces disallowed controls, removes bidirectional and reviewed unsafe invisible formatting characters, trims line ends, collapses excessive blank lines, and truncates on a UTF-8 boundary.
It canonicalizes the truncated prefix again so newly exposed whitespace or line endings cannot bypass durable canonical form while preserving the original truncation signal.
Typed construction and durable decoding share the same canonical-excerpt predicate so an alternate caller or malformed stored row cannot bypass those transformations.
Malformed HTML, invalid charset data, excessive expansion, and empty output fail closed without a raw fallback or attacker-controlled diagnostic.

Migration `0007_candidate_content.sql` persists one strict binary-keyed excerpt row under a restrictive foreign key.
The row contains no raw MIME, raw HTML, provider JSON, attachment data, filename, address, subject, policy value, link, credential, endpoint, or free-form explanation.
The application returns the fixed trust classification `untrusted_email` and validates every durable field and its domain-separated hash.
Fake and exact-driver compare-and-swap operations reject inactive lifecycle, stale source, noncandidate gate, blind replacement, crossed writers, same identity with different output, and malformed durable data.
The exact-driver mutation is attempted once, retains its session while a separate physical connection proves semantic durable visibility, discards an unproven session, and performs no same-invocation replay.

Credential-free literal-loopback tests do not prove the remote Turso Database strict-table, foreign-key, writer-serialization, compare-and-swap, or visibility semantics for migration `0007`.
Remote migration and live excerpt persistence remain prohibited pending later approved evidence.
The validated `retention.excerpt_days` setting is policy only because this inert slice does not schedule or perform deletion.

### Accepted database adapter and inert typed persistence boundary

[ADR 0004](adr/0004-turso-serverless-adapter.md) accepts `tursogo-serverless` v0.0.0-20260817122138-24adc316cdc4 behind a repository-owned adapter.
The adapter is reachable from `account add`, `account list`, `account pause`, `account resume`, and confirmed `account revoke` after environment-selector separation and a credential-free literal-loopback endpoint check.
The internal current-discovery use case can call its typed operations when supplied a handle, but no executable path constructs that composition.
The adapter remains unreachable from health endpoints, doctor, configuration inspection, capability inspection, and executable Gmail synchronization.
Service startup and MCP reach only bounded `ListAccounts` through the operator-gated credential-free literal-loopback composition.
[ADR 0005](adr/0005-append-only-migration-protocol.md) adds an embedded migration ledger and runner that can execute only against a credential-free literal-loopback endpoint.
[ADR 0006](adr/0006-minimum-account-cursor-persistence.md) appends minimum account identity and synchronization-cursor tables and exposes only typed account and cursor operations under the same restriction.
[ADR 0007](adr/0007-versioned-provider-credential-encryption.md) appends a ciphertext-only provider-credential table and exposes only typed credential lookup and compare-and-swap under the same restriction.
[ADR 0009](adr/0009-account-lifecycle-and-revocation.md) appends strict versioned account lifecycle state and exposes only bounded listing, typed lifecycle compare-and-swap, and revoked-only exact ciphertext deletion under the same restriction.
[ADR 0010](adr/0010-atomic-current-discovery-staging.md) appends canonical message, attempt, and staging state and exposes only one bounded aggregate commit, reconciliation, and canonical message lookup under the same restriction.
[ADR 0011](adr/0011-bounded-gmail-current-discovery.md) composes those typed operations with synthetic OAuth and Gmail reads while adding no SQL operation or remote adapter activation.
[ADR 0012](adr/0012-deterministic-persisted-gate.md) appends strict gate-decision state and exposes only typed read, compare-and-swap, and inert evaluation operations under the same restriction.
[ADR 0013](adr/0013-bounded-candidate-content.md) appends strict candidate-content state and composes one bounded read-only Gmail content projection with fail-closed MIME, charset, HTML, and typed persistence operations under the same restriction.
The current-discovery use case, gate evaluator, and candidate-content extractor remain unreachable from every executable runtime caller.
No production URL, live token, real account record, email record, display metadata, plaintext credential, or runtime secret is introduced by these decisions.

The adapter validates the initial endpoint before driver construction.
It keeps URL and token values separate, normalizes `turso` to HTTPS, requires standard verified HTTPS for remote endpoints, rejects credentials in URLs, and limits cleartext HTTP to credential-free literal IPv4 or IPv6 loopback tests.
That policy applies only to the caller-supplied initial endpoint and does not validate a later protocol-provided `base_url`.
Ping has an adapter-owned deadline no longer than 30 seconds and respects a shorter caller deadline.
Migration catalog validation completes before connection acquisition, and credentialed or non-loopback migration execution fails before the first migration request.
The runner embeds reviewed exact-byte SQL, limits catalog and logical ledger data, inspects current state outside a transaction, and applies at most one migration through one bounded no-argument pipeline transaction sequence.
The sequence contains fixed `BEGIN IMMEDIATE`, the exact migration, a bounded transaction-local guard that requires the exact row total, rejects nulls, and counts every expected ledger pair exactly once under the writer lock, an insertion with only a bounded code-derived number and validated lowercase-hex checksum, and fixed `COMMIT`.
The sequence accepts no caller-controlled value, while ledger inspection remains parameterized.
Pipeline responses rejected by the driver, and every purported success that fails semantic terminal proof, return unknown without same-invocation replay.
The pinned driver does not validate the sequence response payload and accepts a false autocommit observation, so success additionally requires a same-session savepoint sequence that acquires main-database writer serialization through a bounded ledger self-assignment, revalidates the exact null-rejecting prefix, transactionally prevents marker regression, sets `PRAGMA user_version`, and proves separate-connection visibility of both the exact ledger and marker.
An unproven apply session is rollback-attempted and forcibly discarded from the pool, while a later explicit invocation can repair a missing marker without replaying committed schema SQL.
A marker ahead of the ledger is rejected as drift.
Every failed sequence attempts rollback but returns unknown because the driver cannot confirm rollback completion even when the rollback call returns nil.
The runner revalidates the exact expected ledger prefix through a separate physical connection after every purported commit.
Returned ping, migration, account, cursor, credential, lifecycle, deletion, current-discovery, gate-decision, candidate-content, and close failures use fixed categories rather than wrapping upstream diagnostics, and close is invoked only once.

These controls do not fix the driver properties reproduced during the earlier evaluation.
The driver can still trust an arbitrary scheme and authority from a protocol-provided `base_url` and send the bearer token to a changed authority or over cleartext HTTP after an HTTPS-to-HTTP downgrade.
It can still reflect valid remote error text internally.
The migration path avoids the driver's background-context `database/sql.Tx` completion methods, and the provenance-pinned local fork gives only stream close a caller-owned context, error propagation, bounded fallback, two-worker join, and terminal idempotence.
The fork does not change transaction completion, redirect policy, protocol-provided authority, remote diagnostic construction, or successful-response allocation.
An unacknowledged sequence or rollback remains uncertain and requires reconciliation on a new explicit invocation.
Successful pipeline bodies, cursor lines, accumulated rows, and individual values still lack repository-owned total limits.

The owner accepts those unresolved risks under identifiers `TURSO-001` through `TURSO-005` in the [known-risk register](known-risks.md).
The acceptance is limited to the exact selected version and current credential-free loopback surface.
Every future storage issue must list the risks it reaches and must not treat the register as proof that the behavior is safe.
Credential-free contracts reproduce protocol-provided authority changes, redirect following, dropped-commit reconciliation, and post-buffer oversized-value rejection.
Those contracts document the remaining attack and failure surface and do not close `TURSO-001` through `TURSO-005`.
Later persistence code must use fixed parameterized SQL, durable uniqueness or idempotency keys, and outcome reconciliation where a write can be ambiguous.

Account IDs are exactly 32 lowercase hexadecimal ASCII characters, provider subjects are opaque case-sensitive visible ASCII values of at most 255 bytes, and Gmail history IDs are canonical positive uint64 decimal text.
The schema enforces those forms with byte counts and explicit embedded-NUL rejection, fixes the provider to `gmail`, makes provider identity binary-unique, and restricts cursor rows to existing accounts.
The application validates every input and decoded database value again.
Account creation never updates identity and attempts at most one fixed parameterized insert after a sentinel-row preflight.
Cursor mutation is available only through one fixed parameterized implicit-transaction compare-and-swap statement that explicitly checks account existence and cannot lower a cursor.
The mutation connection remains reserved while a separate physical connection verifies the exact durable account or next cursor.
An unproven outcome discards the mutation session, returns a bounded unknown category, and is never replayed in the same invocation.

Provider refresh tokens are treated as secret bytes before encryption and as sensitive ciphertext after encryption.
The cryptobox accepts only the canonical bounded keyring grammar and uses standard-library AES-256-GCM with a complete fresh 12-byte nonce read for every encryption.
Authenticated additional data binds the fixed envelope header, internal account ID, provider `gmail`, and purpose `oauth_refresh_token`, so moving a ciphertext between accounts or purposes fails authentication.
The envelope authenticates its version, algorithm, key identifier, nonce, ciphertext, and tag.
Decryption returns fixed invalid-envelope, unknown-key, or authentication categories and never reflects ciphertext, plaintext, account ID, key bytes, or cryptographic diagnostics.
Rotation retains decrypt-only keys until every durable envelope has been re-encrypted and restart-verified under the new active key.
Keyring close overwrites repository-owned key arrays and temporary plaintext buffers where practical, but Go does not guarantee elimination of compiler, stack, register, garbage-collector, or library-internal copies.
The storage boundary accepts only structurally validated ciphertext envelopes, derives the stored key identifier from the envelope, and has no plaintext parameter or field.
Migration `0003` enforces byte bounds, embedded-NUL rejection, canonical key identifier characters, the `igc1.` prefix, and a restrictive ciphertext alphabet before accepting durable text.
These structural database checks do not replace AES-GCM authentication before a credential is used.
Credential replacement preserves a source row only for a nil expected envelope or the same account's exact durable expected envelope, and the conflict update repeats the expected-envelope comparison.
The adapter returns a mutation session to the pool only after an exact one-row acknowledgement and separate exact visibility, while ambiguous or zero-row acknowledgements force discard.

Account lifecycle state and provider revocation add a deliberate credential-action boundary.
Every provider call follows a separately proved revoked-attempting status-and-version claim, uses the fixed Google revocation authority, places the token only in the form body, rejects redirects, makes no retry, and maps all diagnostics to fixed categories.
Only HTTP 200 becomes confirmed, every other proven outcome becomes manual-action-required, and local ciphertext is exact-compare-deleted after either final state.
An interrupted or unproved transition remains restart-visible and fails closed rather than restoring active authority.
Concurrent managers and processes compete for one durable pending-to-attempting claim, and only the proven winner may contact the provider.
A restart from attempting assumes provider completion is ambiguous, never calls the provider again, finalizes manual-action-required, and deletes any exact remaining ciphertext with bounded independent cleanup.
Credential inspection failure after the attempting claim leaves that claim nonterminal until a fresh invocation can re-inspect and exact-delete ciphertext without provider replay.
Revocation rejects a nonterminal lifecycle before mutation or provider contact unless enough integer-version headroom remains for every required intent, claim, and finalization transition.
Terminal maximum-version rows remain eligible for exact residual-ciphertext cleanup because that reconciliation does not mutate lifecycle state.

### Resource exhaustion

Large messages, deep MIME trees, unbounded history, pagination, retry loops, or concurrent requests could exhaust memory, storage, quota, or model budget.
Every input and output path must define size, depth, page, time, retry, and concurrency limits before it is enabled.
The inert current-discovery invocation limits history responses to 1 MiB, message metadata responses to 256 KiB, provider error and refresh responses to 16 KiB, pages to ten, unique messages to 5,000, MIME nodes to 1,000, MIME depth to 32, attempts per GET to four, and total provider attempts to 20,041.
It serializes invocations per constructed use case and performs no concurrent message request.
Historical backfill yields to current-mail synchronization and resumes from durable checkpoints.

### Supply-chain compromise

Dependencies, Actions, tools, and future images could execute attacker-controlled code.
The project minimizes direct dependencies, pins versions and Action SHAs, verifies module checksums, runs vulnerability scanning, and requires an architecture decision record for each direct dependency.

Configuration parsing adds only `go.yaml.in/yaml/v3` v3.0.5, which has no declared transitive modules.
Repository code treats its syntax tree as untrusted, applies independent structure and complexity limits before typed decoding, pins and verifies the module checksum, scans reachable code with `govulncheck`, and retains the upstream license notice in release archives.

The Turso serverless module is pinned to an exact pseudo-version and commit, declares no required modules, is covered by an accepted ADR, and retains its MIT notice in release archives.
The public vulnerability review found no applicable published advisory on 2026-08-17, but source-level authority, diagnostic, cancellation, client-policy, and response-bound risks remain open in the known-risk register.
Any future driver, fork, proxy, or contract image is a new supply-chain boundary that requires exact pins, an accepted ADR, complete license and advisory review, lifecycle fault injection, and a removal plan before use.

The release workflow grants narrow write authority to create one immutable GitHub release.
The original actor and triggering actor must both be the repository owner, the run attempt must be one, and the dispatch must come from `main`.
The requested SHA must equal the workflow SHA, checked-out `HEAD`, current remote `main`, and a successful completed `ci-required` check.
These conditions are checked before building, before draft creation, and immediately before publication.
Repository immutable releases are currently enabled.
Immediately before clicking `Run workflow`, the owner must confirm `Settings > Releases` still shows immutable releases enabled, and the manual dispatch records that approval.
The automatic workflow token has no repository Administration permission, so the workflow uses no external credential and makes no prepublication API claim about the setting.

Release input could attempt shell injection or path manipulation.
Version and commit values use strict allowlist formats, pass through quoted environment variables, and are never interpolated into workflow shell source.
Generated release notes are handled only as GitHub API data.

A compromised Action or SBOM tool could alter artifacts or disclose runner data.
Every executable Action is pinned to a full commit, tools use exact versions, checkout credentials are not persisted, and the release supply-chain decision records licenses and dependency impact.
Repository-owned code validates binary build information, archive metadata, the SPDX document with one application root and one complete reviewed module and standard-library inventory at each exact canonical binary location, the checksum set, and the exact asset set.
Repeated SBOM module rows are accepted only across distinct expected binary locations, never as a same-location duplicate, path alias, escape, inconsistent version, or unreviewed scope.
The SPDX JSON boundary is limited to 4 MiB, 64 container levels, and 131,072 tokens before typed decoding.
It rejects duplicate keys at every object depth and non-exact case aliases of recognized security fields so `encoding/json` overwrite and case-fold behavior cannot change the validated document.

An external tool installer could execute unreviewed shell logic before the intended executable is authenticated.
InboxGate does not use the rejected Syft download Action or an ambient installer.
Repository-owned standard-library code downloads one exact official Linux amd64 archive, verifies its committed SHA-256 before extraction, rejects unsafe archive entries, and executes it only to confirm the exact pinned version.

A draft asset could differ from the locally verified file or change before publication.
The workflow reconstructs the local name, size, and SHA-256 map, downloads all eight remote assets immediately before publication, rechecks `main`, the reserved tag, and draft identity as its final gates, and downloads all published assets again for digest verification.
The target tag is checked against the expected commit after publication.

Publishing is a one-way security boundary because immutable release assets and tags cannot be repaired in place.
The owner manually verifies immutable releases immediately before dispatch, and the workflow reserves the exact tag before creating a draft, uploads and verifies all assets, rechecks every machine-readable final boundary, and performs one publish operation.
After publication, the workflow requires the release object to report immutable state.
If the setting drifted despite the manual check, that verification fails and the owner must treat the release as unsafe.
It never deletes or repairs a failed draft, tag, asset, or attestation automatically.

SBOM timestamps and namespaces are intentionally not reproducible.
Release binaries and archives are byte-reproducible, and artifacts are rejected if the SBOM includes the runner workspace path.

## Assumptions

- The host, Go toolchain, GitHub, Google, Turso, and private network are administered independently and may fail.
- Hermes is authenticated but still receives least privilege because its model and email inputs are not trusted to choose authority.
- Production deployment, OAuth consent, secret creation, live account access, and production database writes require explicit owner approval.
- The current foundation has a health service plus one authenticated stateless MCP route with capability inspection and conditionally gated lifecycle and synchronization-status reads, a one-shot OAuth enrollment command, an inert internal current-discovery use case, an inert deterministic persisted gate, and an inert bounded candidate-content extractor restricted to synthetic providers and credential-free literal-loopback persistence until owner approval, but no remote database activation, live OAuth approval, mail-content MCP tool, scheduler, executable Gmail synchronization, or active excerpt retention.
- Immutable releases are enabled and enforced by GitHub before an owner attempts publication.
- A completed release run is still reviewed as an owner operation and is not a deployment authorization.

## Review triggers

Update this document whenever a change affects credentials, encryption, authentication, authorization, external requests, persisted data, untrusted content, MCP tools, network exposure, or dependency trust.
Every pull request must state whether it changes this model and cite the affected section when it does.
## Candidate-inspection trust boundary

The `mail_list_review_candidates` and `mail_get_gate_reason` tools extend the authenticated MCP boundary to one owner-approved bearer principal with tenant-wide sensitive-read authority.
Account filters only narrow results and cannot authorize an account or another operation.
Email-derived previews are labeled `untrusted_email`, remain untrusted data, and cannot authorize another tool call, URL fetch, secret disclosure, policy change, Gmail mutation, database mutation, review mutation, or external write.
Candidate excerpts are explicitly excluded from both tools.
The application receives only two typed fixed-read methods and has no Gmail, OAuth, mutation, generic SQL, shell, URL-fetching, or provider authority.
Canonical policy-bound cursors, a one-hundred-row scan limit, a ten-candidate output limit, a 65,536-byte response limit, and fixed unavailable errors limit observation and enumeration.
The selected driver can still buffer an oversized successful response before repository checks, so `TURSO-005` remains open for this path.
