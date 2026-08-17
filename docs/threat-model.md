# InboxGate threat model

Status: rejected Turso driver feasibility gate for issue #14.

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
| InboxGate to future database | URL, redirects, protocol authority, responses, query results, credentials, uncertain transport outcomes | Boundary remains disabled until a separate ADR requires verified HTTPS, rejects cleartext remote URLs, limits plain HTTP to credential-free literal-loopback tests, proves same-authority credential handling, bounds typed diagnostics and successful response bodies, cursor lines, rows and values or equivalent streaming, provides caller-controlled cancellation, uses fixed parameterized queries, prevents automatic statement replay, encrypts provider credentials, and preserves migration integrity |
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

### Rejected database boundary

The evaluated `tursogo-serverless` version is not a dependency and no database boundary is active.
A credential-free local experiment proved basic SQL over HTTP v3 interoperability but failed production security and cancellation review.

The driver trusted a protocol-provided `base_url`, replaced the original authority, and attached the bearer token to later requests.
A malicious synthetic loopback response reproduced cross-authority bearer forwarding.
The public API exposed no injectable HTTP client, transport, or authority-policy hook that a repository-owned wrapper could use to fail closed.

Valid JSON error text below the driver's response limit was returned verbatim.
Synthetic token-like text, SQL, values, paths, queries, and sentinels therefore crossed the remote-response boundary into diagnostics.

Commit, rollback, and connection close created background contexts inside the driver and used an HTTP client without a timeout.
Synthetic stalled responses outlived the caller's deadline.
A wrapper timer would abandon the live request and locked connection rather than cancel the operation.

The storage roadmap is blocked by [ADR 0003](adr/0003-turso-serverless-driver-contract.md).
A future production driver or explicitly approved protocol boundary must require HTTPS with standard certificate and hostname verification and reject cleartext remote URLs before request or credential use.
Plain HTTP is limited to literal-loopback credential-free tests and may carry no bearer token or production-derived secret.
The boundary must also prove same-authority credential handling, fail-closed redirects, bounded typed diagnostics, owned limits for successful response body bytes, cursor-line bytes, row counts and individual value bytes or equivalent streaming controls, caller-controlled cancellation for every transaction and close operation, and no replay after uncertain writes.
Later persistence code must also use durable uniqueness or idempotency keys and outcome reconciliation where a write can be ambiguous.

### Resource exhaustion

Large messages, deep MIME trees, unbounded history, pagination, retry loops, or concurrent requests could exhaust memory, storage, quota, or model budget.
Every input and output path must define size, depth, page, time, retry, and concurrency limits before it is enabled.
Historical backfill yields to current-mail synchronization and resumes from durable checkpoints.

### Supply-chain compromise

Dependencies, Actions, tools, and future images could execute attacker-controlled code.
The project minimizes direct dependencies, pins versions and Action SHAs, verifies module checksums, runs vulnerability scanning, and requires an architecture decision record for each direct dependency.

Configuration parsing adds only `go.yaml.in/yaml/v3` v3.0.5, which has no declared transitive modules.
Repository code treats its syntax tree as untrusted, applies independent structure and complexity limits before typed decoding, pins and verifies the module checksum, scans reachable code with `govulncheck`, and retains the upstream license notice in release archives.

The rejected Turso module and prototype libSQL container harness are not retained or distributed.
Any future database driver, fork, proxy, or contract image is a new supply-chain boundary that requires exact pins, an accepted ADR, complete license and advisory review, lifecycle fault injection, and a removal plan before use.

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
- The current foundation has a process-health network service intended only for private deployment but no database driver, OAuth flow, MCP endpoint, scheduler, or provider integration.
- Immutable releases are enabled and enforced by GitHub before an owner attempts publication.
- A completed release run is still reviewed as an owner operation and is not a deployment authorization.

## Review triggers

Update this document whenever a change affects credentials, encryption, authentication, authorization, external requests, persisted data, untrusted content, MCP tools, network exposure, or dependency trust.
Every pull request must state whether it changes this model and cite the affected section when it does.
