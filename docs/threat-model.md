# InboxGate threat model

Status: release supply-chain update for issue #4.

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
| Operator to CLI and configuration | Arguments, paths, YAML, environment names | Strict parsing, bounded input, redacted output, no secret values in YAML |
| Google to synchronization client | HTTP status, headers, metadata, MIME content, history cursors | TLS, narrow response types, size limits, retries, duplicate handling, transactional cursor advancement |
| Email sender to InboxGate | Headers, HTML, text, links, instructions | Treat all content as data, sanitize HTML, truncate content, mark untrusted content |
| InboxGate to Turso | Queries, records, credentials | Parameterized fixed queries, encrypted provider credentials, least privilege, migration integrity |
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

### Resource exhaustion

Large messages, deep MIME trees, unbounded history, pagination, retry loops, or concurrent requests could exhaust memory, storage, quota, or model budget.
Every input and output path must define size, depth, page, time, retry, and concurrency limits before it is enabled.
Historical backfill yields to current-mail synchronization and resumes from durable checkpoints.

### Supply-chain compromise

Dependencies, Actions, tools, and future images could execute attacker-controlled code.
The project minimizes direct dependencies, pins versions and Action SHAs, verifies module checksums, runs vulnerability scanning, and requires an architecture decision record for each direct dependency.

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
- The current foundation has no network service, OAuth flow, database, MCP endpoint, or provider integration.
- Immutable releases are enabled and enforced by GitHub before an owner attempts publication.
- A completed release run is still reviewed as an owner operation and is not a deployment authorization.

## Review triggers

Update this document whenever a change affects credentials, encryption, authentication, authorization, external requests, persisted data, untrusted content, MCP tools, network exposure, or dependency trust.
Every pull request must state whether it changes this model and cite the affected section when it does.
