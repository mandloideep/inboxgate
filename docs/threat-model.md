# InboxGate threat model

Status: accepted credential-free loopback migration runner with known upstream risks for issue #20.

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
| Google to synchronization client | HTTP status, headers, metadata, MIME content, history cursors | TLS, narrow response types, size limits, retries, duplicate handling, transactional cursor advancement |
| Email sender to InboxGate | Headers, HTML, text, links, instructions | Treat all content as data, sanitize HTML, truncate content, mark untrusted content |
| InboxGate to Turso adapter | URL, redirects, protocol scheme and authority, responses, query results, credentials, uncertain transport outcomes | Repository-owned interface, separate URL and token values, verified HTTPS for the initial remote endpoint only, credential-free literal-loopback migration execution only, fixed outer diagnostics, bounded context-aware requests, embedded exact-byte migration checksums, parameterized ledger inspection, one exact atomic transaction sequence with bounded internal literals, no automatic sequence replay, fresh-run reconciliation, and explicit accepted-risk tracking for driver-controlled authority, redirect, response buffering, and close behavior |
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
The listener registers only exact liveness and process-readiness paths with fixed bounded JSON documents.
It has no Gmail, OAuth, database, scheduler, MCP, provider, mutation, operator, URL-fetching, SQL, shell, or static-content route.
Unknown paths, unsupported methods, and request bodies receive fixed errors that never echo request data.
Percent-encoded alternate spellings of a health path remain unmatched and are logged only as the bounded `unmatched` operation.
Configured timeouts, a compiled 16 KiB header limit, a compiled limit of 128 concurrently accepted connections, and the configured request-body bound constrain the standard-library server.
The listener acquires admission before the underlying accept, blocks further application acceptance until a permit is released exactly once by connection close, and unblocks permit waiters during shutdown.

The health routes are unauthenticated because schema v1 has no separate probe credential and the future MCP bearer token belongs to another trust boundary.
They reveal only `live`, `ready`, or `not_ready` and must bind only to an approved private interface or private reverse-proxy path.
The default all-interface listener is not authorization for public exposure.
Detailed database, migration, scheduler, account, provider, secret, or connectivity diagnostics remain absent.

Structured lifecycle and request logs use only bounded event names, allowlisted operations and methods, numeric status and duration, bounded outcomes, and bounded failure reasons.
The implementation omits raw errors and suppresses the standard-library server error logger so request data and listener addresses cannot bypass the allowlist.
It never logs raw paths, queries, hosts, remote addresses, headers, bodies, user agents, configuration paths, listener addresses, YAML-named environment variables, secret presence, account identifiers, provider data, or message data.

Readiness becomes false before graceful shutdown begins.
The first termination signal stops new connections and gives active work a compiled 10-second drain deadline.
A second signal cannot restart or extend that deadline, and an expired deadline forces the server closed with a bounded failure record.
The local `doctor` command constructs the runtime without binding a socket, reading YAML-named environment values, or activating a provider.

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

### Accepted database adapter and synthetic migration boundary

[ADR 0004](adr/0004-turso-serverless-adapter.md) accepts `tursogo-serverless` v0.0.0-20260817122138-24adc316cdc4 behind a repository-owned adapter.
The adapter is present in code but is not reachable from configuration, commands, service startup, health endpoints, capabilities, Gmail, OAuth, or MCP.
[ADR 0005](adr/0005-append-only-migration-protocol.md) adds an embedded migration ledger and runner that can execute only against a credential-free literal-loopback endpoint.
No product-state schema, repository, production URL, live token, account record, or email record is introduced by the decision.

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
Returned ping, migration, and close failures use fixed categories rather than wrapping upstream diagnostics, and close is invoked only once.

These controls do not fix the driver properties reproduced during the earlier evaluation.
The driver can still trust an arbitrary scheme and authority from a protocol-provided `base_url` and send the bearer token to a changed authority or over cleartext HTTP after an HTTPS-to-HTTP downgrade.
It can still reflect valid remote error text internally.
The migration path avoids the driver's background-context `database/sql.Tx` completion methods, but stream close still uses a background context through a private HTTP client without an owned timeout or redirect policy.
An unacknowledged sequence or rollback remains uncertain and requires reconciliation on a new explicit invocation.
Successful pipeline bodies, cursor lines, accumulated rows, and individual values still lack repository-owned total limits.

The owner accepts those unresolved risks under identifiers `TURSO-001` through `TURSO-005` in the [known-risk register](known-risks.md).
The acceptance is limited to the exact selected version and current credential-free loopback surface.
Every future storage issue must list the risks it reaches and must not treat the register as proof that the behavior is safe.
Credential-free contracts reproduce protocol-provided authority changes, redirect following, dropped-commit reconciliation, and post-buffer oversized-value rejection.
Those contracts document the remaining attack and failure surface and do not close `TURSO-001` through `TURSO-005`.
Later persistence code must use fixed parameterized SQL, durable uniqueness or idempotency keys, and outcome reconciliation where a write can be ambiguous.

### Resource exhaustion

Large messages, deep MIME trees, unbounded history, pagination, retry loops, or concurrent requests could exhaust memory, storage, quota, or model budget.
Every input and output path must define size, depth, page, time, retry, and concurrency limits before it is enabled.
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
Repository-owned code validates binary build information, archive metadata, the SPDX document, the checksum set, and the exact asset set.

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
- The current foundation has a process-health network service intended only for private deployment and an embedded migration runner restricted to credential-free literal-loopback tests, but no runtime database activation, remote migration, OAuth flow, MCP endpoint, scheduler, or provider integration.
- Immutable releases are enabled and enforced by GitHub before an owner attempts publication.
- A completed release run is still reviewed as an owner operation and is not a deployment authorization.

## Review triggers

Update this document whenever a change affects credentials, encryption, authentication, authorization, external requests, persisted data, untrusted content, MCP tools, network exposure, or dependency trust.
Every pull request must state whether it changes this model and cite the affected section when it does.
