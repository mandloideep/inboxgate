# ADR 0003: Reject the current Turso serverless driver for production

- Status: Rejected - persistence blocked
- Date: 2026-08-17
- Issue: #14
- Owners: @mandloideep

## Context and need

InboxGate needs remote `database/sql` access to a new Turso Database without CGO or a native client library.
Persistence design cannot begin until the production driver has a credential-free reproducible protocol contract and fails closed at its network and error boundaries.
The proposed driver was `turso.tech/database/tursogo-serverless` at pseudo-version `v0.0.0-20260817073220-04ff3de5e1a8`, source commit `04ff3de5e1a8b65bb7ff43fab05c8f2368577841`.

A credential-free experiment against the official libSQL server proved that the exact driver can execute SQL over HTTP v3 without a Cloud account or token.
The experiment covered connection ping, fixed DDL and DML, values, constraints, default transactions, concurrent writes, connection-close rollback, and restart durability.
That protocol compatibility was necessary but not sufficient for production acceptance.

Independent security and correctness reviews found driver-internal behavior that a repository-owned `database/sql` wrapper cannot safely constrain.
The findings were reproduced end to end with synthetic loopback servers before this decision was changed.

## Decision

InboxGate rejects this driver version for production and blocks all persistence implementation.
The module is not included in `go.mod`, no production connector or storage harness is retained, and no configuration or runtime path opens a database.
Migrations, schema design, credential storage, account persistence, and synchronization cursors must not proceed until a separate architecture issue selects and validates a safe replacement or an upstream release with the required controls.

InboxGate will not work around these findings with reflection, `unsafe`, `go:linkname`, a process-wide default transport override, an in-process reverse proxy, or an unapproved vendored fork.
A maintained fork or protocol proxy would create a new security-critical product boundary and requires its own explicit architecture decision, maintenance ownership, dependency review, and removal plan.

## Blocking findings

### Server-controlled authority can receive the bearer token

SQL over HTTP v3 responses can contain `base_url`.
The pinned driver accepts that value without enforcing the original authority and uses it for later requests.
It then attaches the configured bearer token to the replacement authority.

A synthetic origin server returned a second loopback server as `base_url`.
The next request reached that second authority with `Authorization: Bearer synthetic-bearer-secret`.
The public connector API has no authority-policy callback, redirect validator, or injectable HTTP client that could prevent the disclosure.

### Valid HTTP error text is reflected raw

For a valid JSON non-success response below its 1 MiB read limit, the driver includes the server-provided `message` directly in the returned error.
A synthetic 502 response reflected token-like text, fixed SQL, a private value, a temporary path, a query, and a sentinel verbatim.

A wrapper can replace errors returned by ordinary context-aware calls, but complete sanitization would also need reliable machine-readable classifications and coverage of transaction and close paths.
The authority and cancellation blockers remain even if error wrapping is added outside the driver.

### Transaction completion and close cannot be canceled

The driver creates `context.Background()` internally for `Tx.Commit`, `Tx.Rollback`, and stream close.
Its session uses an `http.Client` with no timeout and exposes no transport or client injection hook.
A synthetic server held `Tx.Commit` and connection close beyond the caller's deadline until the server itself released the response.

Running these methods in a goroutine and returning after a timer would abandon a live request and locked connection rather than cancel the work.
That would leak resources and leave transaction outcome uncertain.
A production wrapper therefore cannot provide truthful bounded shutdown or transaction completion.

### Prototype harness was not accepted

Review also found that the prototype Docker harness could create a container before recording ownership and relied on `DOCKER_CLIENT_TIMEOUT`, which is not an operating-system process deadline.
An accepted future harness must establish exact container ownership before start, use real process deadlines, and prove cleanup through injected create, start, run, test, signal, and timeout failures.
The prototype was removed rather than retained as misleading validation.

Its no-replay regression also exercised an internal ping statement instead of inspecting one fixed DML request on `/v3/cursor`.
Any future driver contract must drop the DML transport response and prove that the exact statement body was submitted only once.

## Alternatives considered

### Accept the protocol experiment

The positive local SQL matrix proves basic interoperability only.
It cannot compensate for bearer-token authority confusion or unbounded transaction and close requests.

### Sanitize errors in an outer connector

An outer wrapper can map some returned errors to safe categories.
It cannot inspect or reject the driver's private `base_url` state, replace the private HTTP client, or cancel background transaction and close calls.

### Override `http.DefaultTransport`

The driver currently creates an HTTP client with a nil transport, but changing the process-wide default transport would affect unrelated HTTP clients and remain vulnerable to upstream implementation changes.
It is not a narrow maintainable security boundary.

### Run a local reverse proxy

A proxy could own authority and timeout policy but would add another network service, credential boundary, lifecycle, and protocol implementation to the product.
That is outside this issue and would require a separate architecture decision.

### Vendor or fork the driver

A fork could add an injectable client, same-authority validation, typed sanitized errors, and context-aware transaction and close methods.
InboxGate does not accept permanent ownership of that security-sensitive protocol code implicitly.
A future issue may evaluate a maintained upstream fix or an explicitly staffed fork.

### Use Cloud credentials in tests

Live Cloud tests would not fix the driver semantics and would violate the credential-free public CI requirement.
They also introduce remote state, quota, cleanup, and secret exposure risks.

## Dependency and supply-chain review

- Rejected module and exact version: `turso.tech/database/tursogo-serverless v0.0.0-20260817073220-04ff3de5e1a8`.
- Module checksum reviewed: `h1:Oz+XVBuGQvTl3ab2cO8hZXNkQpNrrQU9Q770kL4a4xA=`.
- Module-file checksum reviewed: `h1:KWrz0BzLKiXUkLmM5HXyr/gWA8ySNZexfW0NV0GGk0A=`.
- Transitive dependency impact: the rejected module declared Go 1.24.0 and no required modules.
- License: MIT, compatible with InboxGate, but no notice is required because the rejected module is not retained or distributed.
- Published advisories: the Go vulnerability database, OSV, and GitHub Advisory Database had no applicable published record when reviewed on 2026-08-17.
- Maintenance status: the evaluated version was an untagged same-day pseudo-version from the active official Turso repository.
- Removal result: the module, checksums, production connector, contract tests, and container harness were removed before publication and were never staged or committed.

The absence of a published advisory does not reduce the severity of behavior reproduced directly in the selected version.

## Security and privacy impact

Rejecting the driver prevents a server-controlled authority from receiving a Turso bearer token through InboxGate.
It also prevents raw remote error text from entering application diagnostics and prevents unbounded background transaction or close requests from entering shutdown paths.
No database credential, URL, record, Cloud service, or production database was used during the evaluation.
All reproductions used synthetic values and loopback servers.

The database trust boundary remains closed.
Configuration continues to contain environment-variable names only and does not activate a database connection.
No Gmail, OAuth, MCP, Hermes, Vikunja, capability, health, or operator behavior changed.

## Consequences

The storage roadmap is blocked after process health and before migrations.
InboxGate cannot claim Turso production compatibility, and no release may imply an operational database path.
This delay is preferable to persisting credentials and synchronization state through a boundary that cannot enforce authority or cancellation.

A future architecture issue must evaluate at least the following acceptance properties.

- The HTTP client or transport is injectable and owned by InboxGate.
- Production database URLs require HTTPS with standard TLS certificate and hostname verification, and cleartext remote URLs are rejected before any request or credential use.
- Plain HTTP is permitted only for a literal loopback endpoint in a credential-free test, and no bearer token or production-derived secret may be attached in that mode.
- Protocol-provided base URLs are rejected or constrained to an explicitly validated same authority before any credential is attached.
- Redirect behavior is fail-closed and covered by bearer-leak regressions.
- Remote error messages and malformed values map to bounded typed diagnostics without SQL, arguments, tokens, URLs, paths, or raw bodies.
- Successful protocol responses enforce owned limits for total body bytes, cursor-line bytes, row count, and individual value bytes, or stream within equivalent tested memory and disk bounds.
- Commit, rollback, connection close, and stream close accept a caller-controlled deadline or use an owned bounded client whose cancellation is proven end to end.
- A dropped fixed DML response produces one inspected `/v3/cursor` request and no replay.
- The credential-free real-server matrix remains available without claiming libSQL and Turso Database engine equivalence.
- The container harness uses create-then-start ownership, operating-system command deadlines, and deterministic lifecycle fault injection.
- The driver compiles with CGO disabled for all six release targets through the canonical repository check.

## Validation

- Reproduce cross-authority bearer forwarding from a malicious `base_url` response.
- Reproduce raw valid JSON HTTP error reflection with synthetic sensitive fields.
- Reproduce stalled `Tx.Commit` and connection close beyond the caller's deadline.
- Restore the exact pre-evaluation module graph and dependency notices.
- Confirm the CLI, service, configuration, and capability graphs contain no storage driver activation.
- Run `make check`, module verification, vulnerability scanning, `git diff --check`, protected-file checks, and deletion audits.
