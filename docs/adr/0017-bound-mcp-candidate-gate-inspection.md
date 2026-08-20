# ADR 0017: Bound MCP candidate and gate-reason inspection

- Status: Proposed
- Date: 2026-08-20
- Issue: #44
- Owners: @mandloideep

## Context and need

InboxGate can authenticate one approved Hermes bearer principal and expose bounded account and synchronization status.
It cannot yet list current review candidates or inspect why the deterministic gate classified one message.
Candidate metadata, sender and subject previews, account identifiers, message identifiers, gate outcomes, and reason codes are sensitive tenant-wide data derived from untrusted email.

The existing persisted gate decision records source identity, policy-bound input identity, outcome, reasons, and first evaluation time.
The existing canonical message contains the bounded metadata needed to present a message-level candidate without reading candidate-content migration `0007`.
The next account-aware thread-retrieval slice needs the account, thread, and message identifiers from this list.
It does not need an excerpt in this slice.

The current deployment has one human owner and one owner-approved Hermes bearer principal.
There is no multi-principal, delegated-account, role, tenant, or per-account authorization model.
Account filters can safely narrow this accepted principal's tenant-wide read authority but cannot grant or broaden authority.

The selected Turso driver remains subject to accepted risks `TURSO-001` through `TURSO-005`.
ADR 0016 gives stream close a bounded joined lifecycle, but explicit transaction completion and successful-response pre-allocation bounds remain open.
This slice adds two sensitive multi-row or account-aware read paths and must not describe any accepted risk as closed.

The comprehensive tests-only red commit `7f3a80f5fc6f68c50d7d2edbe0384b6c9103546c` predates this proposal and every application, storage-query, MCP, capability, runtime, and documentation implementation change for issue #44.

## Decision

InboxGate will add one typed read-only review-inspection application service.
The service will adapt exactly two conditional MCP tools.

- `mail_list_review_candidates`
- `mail_get_gate_reason`

Both tools require `mcp.enabled`, `capabilities.mail.review_read`, one valid MCP bearer, and the existing credential-free literal-loopback Turso source with no database token.
The tools are absent and unknown when either configuration gate is disabled.
The existing `system_capabilities`, `accounts_list`, and `mail_sync_status` registration rules remain unchanged.

The service receives one consumer-owned source with only two typed operations.
One operation lists bounded current candidate rows from one fixed query.
The other operation inspects one current gate decision from one fixed query.
The service receives no storage handle, SQL, database executor, transaction callback, Gmail client, OAuth client, provider credential operation, candidate-content extractor, synchronization executor, backfill executor, review mutation, clock mutation, or external-write operation.

The application owns request normalization, account-filter validation, current policy validation, cursor encoding and decoding, date filtering, UTF-8 preview construction, defensive copies, response bounds, and fixed errors.
Storage owns only fixed parameterized reads and strict durable row decoding.
MCP owns only closed schemas, typed rendering, fixed error mapping, and the existing outer protocol controls.

## Authorization and activation

The accepted bearer represents the single owner-approved Hermes service identity.
Enabling `mail.review_read` authorizes that identity to read bounded review data for every active enrolled account in the single-owner deployment.
An omitted account filter means every account within that already granted authority.
An account filter narrows the read to one through sixteen exact account identifiers.
It never proves account ownership, grants new authority, or changes the principal.

A future deployment with multiple principals, owners, tenants, delegated accounts, service roles, or per-account grants must replace this decision before activation.
No caller-controlled claim, forwarded header, client metadata, Host value, cursor, message field, or email content may grant authorization.

Capability `mail.review_read` will be marked `implemented` with security classification `sensitive_read`.
Its configuration status is enabled only when both MCP and the existing `capabilities.mail.review_read` value are enabled.
Its required secret names are the bytewise-sorted selected database token, database URL, and MCP bearer environment-variable names.
Only the environment-variable names are represented.
Values, presence, lengths, hashes, fingerprints, prefixes, and suffixes remain undisclosed.
Its required migration is `0006_gate_decisions.sql`.
No YAML key is added.

## Candidate-list request

`mail_list_review_candidates` accepts one closed object with these optional fields.

- `account_ids` contains one through sixteen lowercase 32-character hexadecimal identifiers in strict bytewise order without duplicates.
- `urgency` is `all`, `standard`, or `urgent` and defaults to `all`.
- `internal_date_min_unix_ms` and `internal_date_max_unix_ms` are inclusive integers from zero through `253402300799999`.
- The minimum date cannot exceed the maximum date.
- `page_size` is one through the smaller of `review.maximum_page_size` and ten.
- Omitted `page_size` defaults to the smaller of `review.default_page_size` and ten.
- `cursor` is at most 414 ASCII characters, begins with `igrc1.`, and must be canonical for the exact normalized request and current gate policy.

An omitted `account_ids` field differs from an explicitly empty array.
Omission means every account authorized to the sole principal.
An explicitly empty array is invalid.
Unknown properties, nulls, wrong JSON types, duplicate JSON fields, noncanonical number forms, unsorted or duplicate accounts, alternate account spelling, unsupported urgency, inverted dates, excessive page size, and malformed cursor are invalid parameters.
Validation completes before the source is called.

Urgency `standard` selects only `review_candidate`.
Urgency `urgent` selects only `urgent_review_candidate`.
Urgency `all` selects both candidate outcomes.
The list is message-level and never groups or collapses a Gmail thread.

## Candidate source and bounded scan

Each list call performs exactly one source query and no retry.
The source returns at most 101 rows after one exclusive account, thread, and message key.
The source query selects only active lifecycle rows, canonical messages, and source-current persisted candidate decisions.
It uses a fixed sixteen-slot optional account selector, a closed urgency selector, an exclusive keyset predicate, bytewise ordering, and a parameterized limit of 101.

The application accepts no more than 101 source rows.
It validates strict bytewise order by account ID, Gmail thread ID, and Gmail message ID.
It rejects duplicate, unsorted, excessive, malformed, stale-source, mismatched, or internally inconsistent rows.
It scans at most the first 100 valid rows.
It reclassifies each scanned message with the complete current validated gate policy.
Only a decision whose gate version, source metadata hash, input hash, outcome, and reason codes exactly match current reclassification is policy-current.
Date filters are applied after strict source-row and policy validation.
The application returns at most the requested page size and never more than ten candidates.

The continuation key is the last scanned source row rather than the last returned candidate.
This makes progress deterministic when date filtering or current-policy validation removes every scanned row.
An empty page can therefore contain a continuation cursor.
Pagination is a live durable view and not a frozen snapshot.
Concurrent durable changes can appear or disappear between calls according to their current key and eligibility.

Source errors, cancellation, deadline, malformed rows, excessive rows, invalid current classification, preview failure, cursor failure, or response overflow return one fixed application-unavailable category with no partial result.
No source query or row is retried.

## Cursor format and binding

The cursor text is `igrc1.` followed by canonical unpadded base64url.
Its decoded binary payload contains these fields in order.

```text
version 1 | 32-byte normalized-query digest | 16-byte decoded account ID | 1-byte thread-ID length | thread-ID bytes | 1-byte message-ID length | message-ID bytes
```

Both Gmail identifiers are printable ASCII values from one through 255 bytes.
The 414-character text maximum permits at most 306 decoded bytes.
The fixed cursor fields and two one-byte length fields consume 51 bytes.
The combined Gmail thread-ID and message-ID bytes must therefore be no more than 255.
A source row whose continuation key exceeds that combined bound is unavailable and produces no partial page.
This derived bound is required to satisfy both the approved full-key cursor and the approved 414-character cap.

The normalized-query digest is SHA-256 over a domain-separated canonical version 1 encoding.
The encoding binds the output version, sorted account identifiers or explicit all-accounts marker, urgency, date-bound presence bits and values, page size, and the full current gate-policy fingerprint.
The policy fingerprint binds every field that gate version 1 uses under the same validated policy semantics as classification.

The decoder rejects unknown versions, padding, alternate base64 spelling, trailing bytes, invalid account bytes, zero or excessive identifier lengths, invalid identifier bytes, noncanonical re-encoding, digest mismatch, and payloads that exceed the text or decoded bounds.
Changing any account filter, urgency, date presence, date value, page size, output version, or gate policy invalidates the cursor before a source query.
The cursor is pagination state only.
It is never authentication, authorization, account ownership, durable identity, or a frozen-snapshot token.

## Candidate result

The result contains output version 1, zero through ten candidates, and a nullable continuation cursor.
Every candidate contains only these fields.

- `account_id`
- `gmail_thread_id`
- `gmail_message_id`
- `internal_date_unix_ms`
- `urgency`
- `outcome`
- `sender_display_preview`
- `sender_display_truncated`
- `sender_address`
- `subject_preview`
- `subject_truncated`
- `has_attachments`
- `content_trust` fixed to `untrusted_email`

The sender display preview is at most 256 UTF-8 bytes.
The subject preview is at most 512 UTF-8 bytes.
Truncation occurs only at a valid UTF-8 boundary and records whether source bytes were omitted.
The complete canonical sender address is included only after existing bounded message validation.
Every sender, subject, identifier, outcome, and reason remains sensitive data.
The trust marker applies to every email-derived preview and does not grant instruction authority.

The list does not read migration `0007`, candidate-content rows, or the candidate-content application boundary.
It never returns an excerpt, body, raw HTML, raw MIME, candidate content hash, source kind, extractor version, excerpt limit, truncation state for content, or fetched timestamp.
It also excludes provider subject, lifecycle internals, credential data or presence, synchronization cursor data or presence, endpoint, hostname, URL, private path, RFC Message-ID, recipients, labels, list headers, metadata hash, gate input hash, raw reason JSON, or canonical message JSON.
The complete MCP response remains within 65,536 bytes before HTTP commitment.

## Gate-reason request and result

`mail_get_gate_reason` accepts one closed object with exactly two required fields.

- `account_id` is one lowercase 32-character hexadecimal account identifier.
- `gmail_message_id` is one through 255 printable ASCII bytes.

It accepts no thread ID, record ID, cursor, hash, SQL expression, Gmail query, selector, provider request, URL, or arbitrary field.
Validation completes before the source is called.

Each valid call performs exactly one source query and no retry.
The fixed query joins one active account-aware canonical message and at most one source-current decision.
It can return all four gate outcomes, including `ignore` and `metadata_only`.

The application deterministically reclassifies the canonical message with the current validated gate policy.
`source_current` is true only when the persisted decision's source metadata hash exactly matches the canonical message metadata hash.
`policy_current` is true only when current reclassification exactly reproduces the persisted gate version, source metadata hash, input hash, outcome, and sorted reasons.
Only a result with both facts true is returned.

The result contains output version 1, account ID, Gmail thread ID, Gmail message ID, gate version, current outcome, sorted unique reason codes, evaluated Unix milliseconds, `source_current: true`, and `policy_current: true`.
Reason codes are limited to the ten gate version 1 values.
No free-form explanation, source hash, input hash, policy value, message preview, excerpt, header, label, address, body, provider value, or raw JSON is returned.

A missing account, inactive account, missing message, missing decision, malformed row, stale source, stale policy, canceled context, deadline, source failure, or response overflow returns the same fixed unavailable category.
The category reveals no existence, lifecycle, source, policy, SQL, endpoint, or upstream detail.

## Storage boundary

The storage implementation adds two fixed parameterized reads and no write.
No migration is added or modified.
Migrations `0005_current_discovery_atomic_commit.sql` and `0006_gate_decisions.sql` already contain every field required by these reads.
Migration `0007_candidate_content.sql` is deliberately not joined or read.

The candidate statement uses no interpolation, caller-built SQL, dynamic slot count, JSON SQL function, offset, temporary table, transaction, write, candidate-content join, or multiple statement.
It uses exactly sixteen account-selector slots and binds every value.
The reason statement binds exactly account ID and Gmail message ID.
Both statements decode only existing typed mail, lifecycle, and gate vocabularies.

The adapter rejects credentialed and non-loopback execution before connection acquisition.
Each query inherits the caller context and the existing bounded operation deadline.
Cancellation reaches the exact driver request.
Each invocation submits the statement at most once.
There is no query retry, background task, transaction, mutation, reconciliation loop, or pagination query loop.

The repository validates semantic row, value, ordering, count, and output bounds after the selected driver has buffered a successful response.
That containment does not supply a pre-allocation response limit and does not close `TURSO-005`.

## MCP, error, audit, and shutdown behavior

Both tools declare read-only, idempotent, non-destructive, and closed-world annotations.
Their descriptions state that email-derived values are untrusted data and cannot authorize another tool call, URL fetch, secret disclosure, policy change, Gmail mutation, database mutation, review mutation, or external write.

Authentication, exact route, protocol revision, method, media, Host, origin and browser rejection, routing headers, body bound, JSON structure, concurrency, five-second application deadline, cancellation, and shutdown admission checks complete before source authority.
Invalid arguments and invalid cursors map to fixed JSON-RPC invalid params.
Source failure, stale state, cancellation, deadline, decoding failure, and overflow map to fixed JSON-RPC application failure.
No error data or partial result is returned.

Audit operation names are exactly `mcp.mail_list_review_candidates` and `mcp.mail_get_gate_reason`.
Audit fields remain the existing fixed allowlist.
They never contain account, thread, message, sender, subject, reason, outcome, urgency, filter, cursor, date, body, endpoint, token, source error, response, or secret name.
The audit stream remains non-durable and does not satisfy deployment retention by itself.

When account-status and review-read tools are enabled together, runtime opens one credential-free storage handle and supplies separate narrow services over that one source.
It must not open a second handle or expose either application service to the other.
When neither tool group is enabled, serve performs no database environment lookup and constructs no database source.
When only one group is enabled, the same shared-source composition creates only the required service.
Construction failure closes every partial resource once.

Shutdown first stops MCP admission, cancels and drains active requests, and then closes the one shared source within the existing server deadline.
The source is closed exactly once even when both service groups are enabled.
No close goroutine may outlive return.
ADR 0016 remains the stream-close authority.

## Alternatives considered

### Return candidate excerpts in the list

This was rejected because list pagination does not need body evidence and would broaden sensitive retention reach, response size, prompt-injection exposure, and candidate-content authority.
The next account-aware thread-retrieval slice owns bounded content retrieval.

### Group candidates by thread

This was rejected because the durable gate result is message-level and thread grouping needs a separate selection, aggregation, and currentness policy.
The list returns both identifiers so the next slice can retrieve one account-aware thread explicitly.

### Use offset pagination

This was rejected because concurrent insertion or removal can duplicate or skip positions and because offsets reveal storage mechanics.
The selected exclusive bytewise keyset is bounded and opaque.

### Store a server-side pagination snapshot

This was rejected because it adds durable or in-memory session state, cleanup, expiry, authorization binding, and another mutation or lifecycle boundary.
The accepted list is a documented live durable view.

### Sign or encrypt the cursor

This was rejected because the cursor contains only identifiers already returned to the authorized caller and is independently bound to the normalized request and policy by a digest.
Authentication and authorization remain outside the cursor.
A future multi-principal design must revisit whether principal binding or authenticated cursor integrity is required.

### Read candidate-content rows for preview text

This was rejected because sender and subject previews already exist in canonical message metadata and candidate-content migration `0007` is outside this tool's authority.

### Pass a storage handle to MCP

This was rejected because the handle carries mutation, credential, migration, and broader read authority.
MCP receives only the application service.

### Add generic filtering or SQL

This was rejected because arbitrary selectors, expressions, SQL, Gmail queries, or caller-built predicates would broaden authority and weaken deterministic bounds.

## Dependency and supply-chain impact

This decision adds no direct, indirect, tool, test, Action, container, parser, SQL-mock, code generator, or ambient-executable dependency.
It uses the Go standard library and the already accepted exact MCP SDK, configuration, gate, mail, storage adapter, and provenance-pinned Turso fork.
The selected module list, versions, graph, checksums, local replacement, licenses, notices, workflows, container inputs, and release tools remain unchanged.

No dependency or notice edit is authorized by this decision.
Any resolved graph change, new import requiring another module, native library, CGO path, generator, external executable, or notice requirement stops implementation pending an amended accepted ADR.

## Security and privacy impact

This decision adds tenant-wide sensitive read authority for the one approved bearer principal.
It discloses opaque account, Gmail thread, and Gmail message identifiers, internal dates, sender and subject previews, complete canonical sender addresses, attachment presence, deterministic outcomes, reason codes, and evaluation timestamps.
Those values can reveal account activity and message context even without a body excerpt.
They require authentication, private routing, TLS, secret storage, audit handling, and explicit deployment approval before live use.

Every email-derived value remains untrusted data.
No returned value may authorize Gmail mutation, a review write, task creation, URL fetching, shell execution, SQL, credential disclosure, provider access, configuration change, or another MCP tool call.
No Gmail or OAuth request is made.
No candidate-content row is read.
No durable state is written.

`TURSO-001` remains open because a protocol response can change scheme or authority.
The credential-free literal-loopback runtime carries no database bearer token, but this does not add same-authority or no-downgrade enforcement.

`TURSO-002` remains open because driver diagnostics can contain SQL and sensitive values.
The storage and MCP boundaries replace every returned failure with fixed categories and never expose the upstream diagnostic.

`TURSO-003` remains open for explicit transaction completion.
These reads use no transaction or mutation and reuse ADR 0016 for bounded stream close.

`TURSO-004` remains open because the driver retains its general private HTTP client and redirect policy.
Credential-free literal-loopback containment remains unchanged.

`TURSO-005` is broadened because a successful candidate query can buffer multiple sensitive rows and values before repository bounds apply.
The source and application reject excessive rows and values after buffering but do not claim pre-allocation containment or remote suitability.

Credential-free exact-driver tests do not prove remote Turso Database behavior, pre-allocation limits, redirect rejection, same-authority enforcement, or live suitability.
Remote Turso, database tokens, live data, live Gmail, production secrets, deployment, and release remain prohibited.

## Capability-surface impact

| Surface | Decision |
| --- | --- |
| Application | One typed read-only review-inspection service |
| Storage | Two fixed typed reads with no mutation |
| MCP | Two conditional sensitive-read tools |
| Configuration | Reuse `mail.review_read`; no new key |
| Gmail and OAuth | No request and no credential read |
| Candidate content | Not read or returned |
| Review state | Not created, inferred, mutated, or filtered |
| Synchronization and backfill | Not executed |
| Health | Unchanged |
| Audit | Two fixed non-durable operation names |
| SQL, shell, URL fetch, Vikunja, A2A | No authority |
| Deployment and release | Not authorized |

## Rollback, removal, and deletion

Setting `capabilities.mail.review_read` to false removes both tools and avoids their source authority after restart.
Setting `mcp.enabled` to false removes the complete MCP surface.
Redeploying the previously validated binary is the operational rollback.
No schema, row, provider, credential, cursor, gate decision, or candidate-content rollback is required.

This issue deletes, renames, truncates, and replaces no pre-existing file.
No deletion request is needed.
Removing future review-inspection application, storage, MCP, tests, or documentation requires a separate deletion-aware issue and owner action under `DELETION_REQUESTS.md`.

## Consequences

The approved Hermes principal can discover a bounded current candidate page and inspect one current deterministic gate reason without receiving a body excerpt or broader storage authority.
Current policy changes invalidate old cursors and make stale decisions unavailable until the inert evaluator persists a current decision through a separately authorized caller.
Live keyset pagination can produce empty continuation pages and can reflect concurrent durable changes between calls.

The selected cursor size creates an explicit combined identifier bound for continuation keys.
A candidate with a combined Gmail thread and message key above 255 bytes fails the complete call instead of producing an unpageable or lossy cursor.

The service remains limited to the one owner-approved principal and credential-free literal-loopback storage.
It is not deployment approval and does not establish multi-principal authorization, remote database readiness, live Gmail access, review writes, thread retrieval, or release readiness.

## Stop conditions

Implementation must stop before production behavior if the cursor cannot bind the complete normalized request and policy within the accepted bound, a source row cannot be represented without loss, or the two fixed reads require dynamic SQL, a migration, or candidate-content access.
Implementation must also stop if it needs a dependency, notice edit, database token, remote endpoint, Gmail or OAuth request, content excerpt, arbitrary selector, storage handle in MCP, mutation, retry, background worker, shell, URL fetch, Vikunja operation, or live credential.
Any such need requires an amended proposed decision and explicit orchestrator acceptance before continuing.

## Validation

The preserved red suite covers exact tool inventory, schemas, annotations, untrusted descriptions, authentication-before-source, zero calls on rejected input, selector bounds, urgency, dates, page size, cursor canonicality, request and policy binding, exclusive continuation, and zero, one, ten, one hundred, and one hundred one rows.
It also covers empty continuation pages, ordering, duplicate and malformed row rejection, all outcomes and reasons, source and policy staleness, UTF-8 preview boundaries, response overflow, content and private-field absence, defensive copies, one source call, no retry, cancellation, deadlines, shutdown, fixed SQL shape, shared-source composition, fixed audits, capability truth, documentation, and forbidden-authority absence.

Bounded fuzz targets cover request and cursor decoding, preview truncation, storage-row decoding, and MCP envelopes.
Every target must be explicitly invoked by `make test-fuzz` and therefore by `make check`.

After acceptance, required validation includes focused application, storage, MCP, configuration, command, server, and real-process tests with repetition.
Race tests must cover concurrent calls, pagination, cancellation, handler close, one shared-source close, and shutdown.
Credential-free literal-loopback tests must run with both Turso environment variables absent and must inspect the exact selected driver statements and parameters.

Run `go mod tidy -diff`, `go mod verify`, the bounded fuzz targets, `make check`, and `git diff --check`.
Verify the module list and graph are unchanged, vulnerability scanning finds no reachable advisory, all six CGO-disabled targets build, and the canonical Linux amd64 release contract passes.
Audit dependencies, workflows, migrations, protected files, notices, secrets, real identifiers, private URLs, forbidden authority, punctuation, coauthors, and deletions.

## Owner action

OWNER ACTION: explicit orchestrator acceptance of this proposed ADR is required before any application, storage-query, MCP, capability, runtime, or documentation production change.
No owner credential, provider setup, remote database, live account, deployment, or release action is required for implementation, review, merge, or credential-free validation.
No secret value may be requested or pasted.
