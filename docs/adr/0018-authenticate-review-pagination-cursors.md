# ADR 0018: Authenticate review pagination cursors

- Status: Accepted
- Date: 2026-08-20
- Issue: #44
- Owners: @mandloideep
- Amends: ADR 0017 cursor format and cursor-signing alternative only

## Context and need

ADR 0017 binds each review-list continuation cursor to the normalized request, complete current gate policy, and last scanned source key.
The accepted version 1 representation places a deterministic normalized-query digest directly in caller-visible cursor bytes.
The review boundary should instead provide authenticated opaque binding without exposing a reusable policy-derived value or accepting caller-generated binding material.

InboxGate runs one review-inspection service for one process runtime.
The cursor does not need to survive process restart because pagination is already a live durable view rather than a frozen snapshot.
No owner-managed cursor secret, durable cursor record, configuration field, environment-variable name, migration, or external key service is needed.

The tests-only independent-review commit `2a2580b` preserves the required regression and construction, binding, restart, and failure contracts before this decision changes production cursor behavior.
The private review rationale remains outside public issue, pull request, audit, log, and documentation content.

## Decision

InboxGate will authenticate every review-list cursor with HMAC-SHA-256 from the Go standard library.
Each production review-inspection service construction will obtain exactly 32 random bytes from `crypto/rand` before returning a usable service.
That byte array is the cursor MAC key for the lifetime of the one service instance and therefore the one review-enabled process runtime.
The service owns the key and does not expose it to MCP, storage, configuration, logs, audits, results, errors, capabilities, or callers.

Production construction has no fallback key, constant key, derived key, environment lookup, retry, or partially initialized service.
Failure to obtain exactly 32 random bytes returns one fixed construction-unavailable category before MCP binding or source access.
Tests may use a package-private constructor with an exact 32-byte synthetic key or a failing synthetic entropy reader.
No exported option or runtime path may inject caller, configuration, environment, MCP, storage, or email bytes as key material.

## Cursor version and format

The authenticated cursor uses the text prefix `igrc2.` followed by canonical unpadded base64url.
Version 1 cursors are rejected after this amendment is implemented.
The decoded version 2 payload contains these fields in order.

```text
version 2 | 16-byte decoded account ID | 1-byte thread-ID length | thread-ID bytes | 1-byte message-ID length | message-ID bytes | 32-byte HMAC tag
```

The HMAC input is a domain-separated canonical version 2 encoding of the normalized query followed by the complete serialized continuation key.
The normalized query binds the output version, sorted account identifiers or explicit all-accounts marker, urgency, minimum-date presence and value, maximum-date presence and value, page size, and complete current gate-policy fingerprint.
The continuation key binds the exact account, Gmail thread, and Gmail message bytes represented in the payload.

The MAC tag is computed with HMAC-SHA-256 and verified with `crypto/hmac.Equal` before a source query.
No normalized-query digest, policy fingerprint, key fingerprint, entropy fingerprint, or partial MAC is returned separately.
Every parse, canonicality, version, length, key, query-binding, or MAC failure maps to the same fixed invalid-request category with zero source calls.

The 414-character cursor limit remains unchanged.
The version byte, decoded account ID, two identifier-length bytes, and 32-byte MAC consume the same 51 fixed decoded bytes as the version 1 representation.
The combined Gmail thread-ID and message-ID bound therefore remains 255 bytes.
All existing printable-ASCII, canonical base64url, no-padding, no-trailing-byte, and exact re-encoding requirements remain in force.

## Restart, rotation, and memory lifecycle

A process restart constructs a new random key and invalidates every cursor from the previous process.
Two concurrently constructed service instances use independent keys and reject each other's cursors.
Operational rotation is therefore a normal process restart and requires no secret distribution or owner action.
Rolling replacement can invalidate an in-flight pagination sequence, which returns the same fixed invalid-request response and requires the authorized caller to restart listing from the first page.

Go does not guarantee zeroization of copied stack or heap values.
The implementation will keep the key in one fixed-size service field, avoid converting it to a string or slice returned to another layer, never serialize it, and never claim complete zeroization.
Adding a service close method solely for best-effort overwrite is rejected because it would broaden shutdown ownership without guaranteeing removal of compiler or runtime copies.
Process termination remains the reliable end of the key lifetime.

## Authorization and authority boundaries

The cursor remains pagination state only.
It is not authentication, authorization, account ownership, principal delegation, durable identity, or a frozen-snapshot token.
The existing MCP bearer and dual capability gate remain the only caller authorization boundary.
The keyed representation does not grant a cursor holder access to another account, tool, source, process, or policy.

MCP receives no cursor-key operation and storage receives no cursor or key authority beyond the already typed exclusive continuation key.
No Gmail request, OAuth operation, Turso write, remote Turso access, review mutation, arbitrary SQL, shell execution, URL fetch, external key call, or background task is added.

## Alternatives considered

### Retain the deterministic version 1 digest

This was rejected because authenticated opaque binding is stronger and available without new operational state.
The replacement avoids returning a reusable policy-derived binding value while retaining request and policy invalidation.

### Add an owner-managed environment secret

This was rejected because cursors do not need restart persistence and a new secret would add provisioning, storage, rotation, validation, recovery, and release-readiness obligations.
No configuration or environment-variable name is justified for this process-local state.

### Persist a cursor-signing key

This was rejected because durable key storage would add a migration, encryption and recovery decisions, mutation authority, rollback coordination, and a longer compromise lifetime.
Restart invalidation is an acceptable pagination property.

### Encrypt the cursor

This was rejected because the continuation identifiers are already returned to the authorized caller and confidentiality is not required for those identifiers.
Authenticated binding is sufficient and simpler.

### Store server-side pagination sessions

This was rejected because it would add mutable state, expiry, cleanup, capacity, synchronization, and authorization binding to a live-view read.

## Dependency and supply-chain impact

This decision adds no direct, indirect, tool, test, Action, container, parser, generator, or native dependency.
It uses only the Go standard-library `crypto/hmac`, `crypto/rand`, and `crypto/sha256` packages.
The selected module versions, graph, checksums, Turso replacement, licenses, notices, workflows, base images, and release tools remain unchanged.
No dependency ADR, notice edit, module edit, or lockfile edit is authorized.

## Migration, configuration, and owner impact

No schema or data migration is added or modified.
No configuration key, capability, secret environment-variable name, secret-store entry, owner credential, provider setting, redirect URI, deployment value, or release input is added.
Owner readiness must state that review pagination restarts from the first page after any service restart and that there is no cursor-key owner action.
Configuration and capability output continue to contain no cursor-key fact, value, presence bit, version, hash, or fingerprint.

## Security and privacy impact

This amendment changes caller-visible pagination from deterministic digest binding to authenticated opaque binding.
It reduces exposed policy-derived material and rejects cursor modification before storage access.
The per-process key is sensitive in memory but is never accepted from configuration or emitted to output.

The threat model must record the process-local cursor MAC key, restart invalidation, fixed construction failure, constant-time MAC comparison, and the lack of guaranteed Go memory zeroization.
The existing tenant-wide sensitive-read authority, one approved bearer, untrusted-email boundary, response bounds, fixed errors, audit restrictions, and Turso accepted risks remain unchanged.
This amendment does not make deployment, remote Turso, live Gmail, production credentials, or release safe or approved.

## Rollback and removal

Operational rollback redeploys the previously validated binary.
Because each process creates an independent key, rollback also invalidates cursors from the replaced process.
No durable key, row, schema, configuration, secret-store entry, or owner credential needs rollback.

Disabling `capabilities.mail.review_read` removes both review tools and avoids cursor construction after restart.
Disabling MCP removes the complete MCP surface.
This amendment deletes, renames, truncates, and replaces no pre-existing file.
No deletion request is needed.

## Consequences

Review cursors become process-local and cannot continue across restart or independently constructed service instances.
Authorized callers may need to restart a bounded live-view listing after routine process replacement.
The complete request, policy, and continuation key remain bound without a returned normalized-query digest.

Construction gains one operating-system entropy read and one fixed failure path.
Cursor encoding and decoding gain HMAC computation but no network, storage, secret-management, or dependency overhead.
The existing cursor size and combined Gmail identifier bound remain unchanged.

## Stop conditions

Implementation must stop if production needs an owner-managed key, environment-variable name, durable key, migration, dependency, external entropy service, configuration option, exported key injector, cursor persistence, storage mutation, or additional authority.
Implementation must also stop if the complete normalized query, complete gate policy, and exact continuation key cannot be authenticated within the accepted cursor bound.
Any such need requires a new proposed decision and explicit orchestrator acceptance.

## Validation

The preserved regression must prove that independently constructed services emit non-interchangeable cursors and reject each other's cursors with zero source calls.
Tests must use fixed synthetic keys to prove canonical version 2 bytes, exact HMAC binding, round trip, exclusive continuation, and unchanged 414-character and 255-byte bounds.
Mutation tests must cover every payload field and MAC byte, alternate base64 spelling, padding, truncation, extension, unknown version, and wrong key.

Binding tests must independently change account selectors, all-accounts presence, urgency, minimum-date presence and value, maximum-date presence and value, page size, output version, and every current gate-policy field.
Every mismatch must return the fixed invalid-request category with zero source calls and no partial result.
Construction tests must prove exact 32-byte entropy consumption, fixed failure on entropy error or short read, no source call, no handler bind, and no key material in errors, logs, audits, capabilities, or results.

Restart and concurrency tests must prove independent service keys, same-service concurrent encode and decode safety under race detection, and expected pagination restart behavior.
Existing exact-driver, response-bound, cancellation, shutdown, audit, authority-absence, credential-free loopback, fuzz, and real-process tests remain required.
Run focused repetitions, the bounded fuzz targets, the full race suite, `make check`, the canonical release contract where applicable, and `git diff --check`.
Verify that dependencies, workflows, migrations, protected files, notices, capabilities, configuration, owner secret names, and deletion requests are unchanged.

## Owner action

OWNER ACTION: explicit orchestrator acceptance of this proposed ADR amendment is required before cursor production behavior changes.
No credential or secret value is required for acceptance, implementation, tests, review, merge, or credential-free validation.
No secret value may be requested or pasted into chat, issues, pull requests, logs, or documentation.
