# ADR 0013: Persist bounded sanitized candidate content

- Status: accepted for credential-free inert extraction
- Date: 2026-08-19
- Issue: #36

## Context and need

InboxGate persists canonical Gmail metadata and deterministic gate decisions, but later review tools need bounded message evidence without fetching or interpreting hostile provider content themselves.
Candidate content is sensitive untrusted email data and can contain prompt injection, malformed MIME, active HTML, hidden text, unsafe Unicode controls, and resource-exhaustion inputs.
The extraction boundary must prove current account authority and a current candidate decision before one fixed read-only Gmail request, then bind durable content to the exact authority, metadata, decision, extractor, and configured size identities.

The selected Turso driver remains subject to open risks `TURSO-001` through `TURSO-005`.
The adapter remains inert, and credential-free literal-loopback tests do not execute a remote Turso Database engine.

## Decision

Add one internal candidate-content extractor with no command, scheduler, service, HTTP, health, capability, or MCP caller.
The extractor accepts one typed account ID, one bounded Gmail message ID, and an excerpt limit from 1,024 through 65,536 bytes.
It reads an active lifecycle, canonical message, and current persisted gate decision before reading and authenticating the provider credential.
Only `review_candidate` and `urgent_review_candidate` are eligible.
It refreshes one access token through the accepted OAuth boundary, then re-reads lifecycle, message, and decision and requires the exact prior lifecycle version, record identity, metadata hash, gate version, gate input hash, and candidate outcome.

The only content request is the existing Gmail `users.messages.get` authority with an escaped message ID, `format=FULL`, and a repository-owned finite `fields` selector.
The selector contains only message ID, thread ID, MIME type, Content-Type header name and value, filename, body size, body data, attachment ID, and nested parts.
The request is a bodyless GET using the existing proxy-disabled, redirect-rejecting, fresh nonpersistent HTTP/1 transport and 15-second attempt deadline.
The response is limited to 1 MiB, the decoded selected part is limited to 512 KiB, the tree is limited to 1,000 nodes and 32 levels, and the request is attempted no more than four times under the already accepted retry classes.
No attachment request exists, and any part with a filename or attachment ID is ineligible.

The MIME walk is deterministic in provider order across the complete bounded tree.
The first eligible inline `text/plain` part wins, and the first eligible inline `text/html` part is used only when no eligible plain part exists.
Each selected part requires exact canonical unpadded Gmail base64url, exact nonnegative declared size, and decoded-size agreement.
The only accepted charsets are UTF-8, US-ASCII, ISO-8859-1, and Windows-1252.
A missing charset defaults to US-ASCII for both selected media types.
Duplicate Content-Type headers, conflicting media types or charsets, malformed parameters, unknown charsets, invalid UTF-8, invalid US-ASCII, and undefined Windows-1252 bytes fail closed.

The HTML converter is a repository-owned bounded state machine and does not implement browser parsing or error recovery.
It accepts balanced start and end tags, quoted or unquoted bounded attribute values, comments, and named or numeric text entities from a closed safe set.
It rejects malformed nesting, unterminated tokens, declarations other than comments, processing instructions, duplicate attributes, malformed entities, excessive token bytes, and ambiguous syntax.
It discards complete subtrees for `script`, `style`, `template`, `noscript`, `svg`, `math`, `head`, `form`, `object`, `embed`, `iframe`, and `canvas`.
It also discards elements with `hidden`, `aria-hidden=true`, or an inline style containing a case-insensitive declaration exactly equivalent to `display:none`, `visibility:hidden`, or `opacity:0` after bounded ASCII whitespace removal.
It emits only decoded text and deterministic newlines around a closed block-element set.
Attributes, links, URLs, images, CSS, forms, scripts, event handlers, and markup are never emitted.

The shared plain-text canonicalizer converts CRLF and CR to LF, replaces NUL and disallowed controls with U+FFFD, removes reviewed bidirectional and unsafe invisible formatting characters, trims trailing horizontal whitespace on every line, trims the whole result, and collapses runs of more than two line feeds to two.
An empty result is unavailable.
Final truncation occurs only at a UTF-8 boundary and records whether canonical bytes exceeded the configured limit.

Candidate content version 1 stores the extractor version, canonical record ID, source metadata hash, gate version, gate input hash, source kind, excerpt, excerpt byte count, configured limit, truncation flag, content hash, and first fetched-at Unix milliseconds.
The application view always reports the fixed trust classification `untrusted_email` without storing a caller-controlled trust value.
The content hash is lowercase SHA-256 over `inboxgate/candidate-content/v1`, one NUL byte, big-endian extractor and gate versions, and big-endian length-prefixed source kind, excerpt limit, truncation byte, and exact excerpt bytes.
The hash does not grant authority and exists only for integrity and compare-and-swap identity.

Append migration `0007_candidate_content.sql` without modifying migrations `0001` through `0006`.
The strict `WITHOUT ROWID` table stores one row per canonical record ID under a restrictive foreign key.
SQL constraints enforce binary collation, version and timestamp bounds, lowercase hashes, the closed source-kind vocabulary, Boolean representation, UTF-8 excerpt byte accounting, configured limit range, excerpt length, and NUL rejection.
Application decoding enforces the complete canonical value before a row crosses the storage boundary.

Expose only a typed current read and a typed compare-and-swap commit.
The read joins account lifecycle, canonical message, gate decision, and candidate content and marks content current only when the lifecycle is active, metadata identity matches, the persisted gate is current and candidate, extractor version is 1, and the stored limit equals the requested limit.
A stale row may be returned only with `Current` false for reconciliation.
Insert requires no existing row.
Replacement requires the exact prior extractor version, source metadata hash, gate input hash, excerpt limit, and content hash.
An exact semantic result is idempotent and preserves its first fetched timestamp.
The commit joins the exact active lifecycle version, canonical message identity, metadata hash, gate version, gate input hash, and candidate outcome in the mutation statement.
Blind replacement, a changed source, a noncandidate gate, inactive lifecycle, same identity with different output, malformed durable data, and crossed writers return fixed typed outcomes.

The Turso mutation is attempted once per invocation.
Its connection remains reserved while a separate physical connection proves exact durable visibility.
An unproven mutation session is discarded, no same-invocation replay occurs, and a fresh invocation reconciles by reading durable state before considering another mutation.

## Alternatives considered

Fetching content inside future MCP handlers would duplicate authority, MIME, charset, HTML, and resource policy at a protocol boundary.
The selected inert application use case centralizes that policy before any protocol exists.

Using the standard library `html` packages is not possible because the standard library does not provide an HTML parser or tokenizer.
Adding `golang.org/x/net/html` would consume an unapproved dependency and the repository's reserved dependency budget.
The selected bounded fail-closed state machine deliberately accepts less HTML and never performs browser-compatible recovery.

Storing raw MIME, raw HTML, multiple alternatives, snippets, attachments, or provider JSON would broaden sensitive retention and later authority.
The selected value stores one bounded canonical plain-text excerpt only.

Treating malformed HTML as plain text would retain markup, attributes, links, and active-content text.
The selected behavior fails closed without a raw fallback.

Retrying an uncertain database mutation could cross a writer or reinterpret state created by the uncertain attempt.
The selected protocol performs one mutation attempt and separate physical proof.

## Dependency and supply-chain review

No direct, indirect, tool, Action, container, parser, charset, SQL-mock, or ambient-executable dependency is added or changed.
The Go standard library and the repository's existing exact dependency graph are sufficient.
Module files, checksums, notices, workflow pins, and container inputs remain unchanged.
Removal stops calling the inert extractor and leaves append-only migration history and durable rows intact.

## Security and privacy impact

This decision adds the first Gmail body-content projection and first persisted email excerpt.
Every body and excerpt is sensitive untrusted email data and never an instruction or authority signal.
Content cannot authorize Gmail mutation, arbitrary provider access, SQL, shell execution, URL fetching, configuration changes, secret disclosure, or an MCP tool.
Raw content, excerpts, HTML, identifiers, tokens, endpoints, and provider errors are excluded from logs, metrics, diagnostics, and fixed errors.

The selected projection excludes snippets, arbitrary headers, attachment retrieval, raw MIME, and mutation methods.
Fixed response, tree, token, decoded-body, output, retry, and deadline bounds contain resource exhaustion.
Fail-closed MIME, charset, HTML, and durable decoding contain parser ambiguity and stored-data corruption.
Lifecycle and gate rechecks plus the exact commit join prevent content from becoming current after authority or eligibility changes.

`TURSO-001` through `TURSO-005` remain open and now cover the more sensitive candidate-content query path.
The existing fixed diagnostics, parameterized statements, one-attempt mutation, separate physical proof, no replay, strict decoding, and session discard remain containment rather than closure.

Retention setting `retention.excerpt_days` remains validated policy only.
This inert slice does not schedule or perform deletion, and activation must not claim retention enforcement until a separately approved mechanism exists.

## Rollback and removal

No pre-existing file is deleted, renamed, truncated, or replaced.
Migrations `0001` through `0006` remain byte-identical.
Migration `0007` is append-only, so application rollback stops using the extractor and typed content operations while leaving schema and rows intact.
Only the repository owner may authorize destructive schema downgrade, durable content deletion, or file removal through `DELETION_REQUESTS.md`.

## Consequences

Later bounded review tools can consume one typed source-bound `untrusted_email` excerpt without implementing provider or parser policy.
Metadata, gate, lifecycle, extractor, and configured-limit changes make persisted content stale and require explicit reconciliation.
The fail-closed tokenizer rejects some HTML that browsers would recover, which is an intentional security and determinism tradeoff.

The extractor remains inert because no executable or capability can call it.
Live Gmail, remote Turso, credentials, deployment, retention deletion, MCP transport, and release remain outside this decision.

## Validation

The preserved tests-only red commit predates this accepted decision and every migration or production change.
Tests cover eligibility before provider contact, lifecycle and source races, exact request projection, attachment exclusion, MIME depth and count, plain preference, HTML fallback and blocked subtrees, malformed HTML, all supported charsets, canonical base64url and size agreement, Unicode and control normalization, UTF-8 truncation boundaries, known content-hash vectors, fake and exact-driver compare-and-swap behavior, uncertain durability, fixed diagnostics, and runtime inertness.
Focused repetition, race tests, exact-driver tests, migration checksums, `make check`, diff validation, dependency inventories, and all six CGO-disabled release-target builds must pass before merge.
