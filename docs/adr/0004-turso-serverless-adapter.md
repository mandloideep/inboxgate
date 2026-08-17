# ADR 0004: Adopt the remote Turso Database driver behind an adapter

- Status: Accepted with known risks
- Date: 2026-08-17
- Issue: #18
- Owners: @mandloideep
- Supersedes: the persistence-blocking decision in [ADR 0003](0003-turso-serverless-driver-contract.md) for the newer version selected here

## Context and need

InboxGate needs direct remote access to a new Turso Database through `database/sql` without CGO or a native client library.
The current official [Turso Go reference](https://docs.turso.tech/sdk/go/reference) and [Go quickstart](https://docs.turso.tech/sdk/go/quickstart) select `tursogo-serverless` for direct remote access to the Turso Database rewrite.
It distinguishes that package from `tursogo`, which provides a local database and optional Cloud push and pull, and from `libsql-client-go`, which targets the legacy libSQL engine.

ADR 0003 rejected an earlier `tursogo-serverless` pseudo-version after credential-free tests reproduced authority, diagnostic, and cancellation problems that an outer wrapper could not fix.
The newer selected version retains those unresolved properties.
The repository owner explicitly accepts them so the project can proceed with Turso, provided that they stay visible in a dedicated risk register and the driver remains replaceable.

This decision accepts an inert connection adapter only.
It does not accept migrations, schemas, repositories, live credentials, runtime activation, production readiness, or a Turso Cloud connection.

## Decision

InboxGate adopts `turso.tech/database/tursogo-serverless` at exact pseudo-version `v0.0.0-20260817122138-24adc316cdc4`, source commit `24adc316cdc4ebf93d90b94dbfda727195540497`.

The consuming `internal/storage` package owns a narrow `Adapter` and `Handle` contract.
The Turso implementation keeps `database/sql` and all SDK construction inside `internal/storage/turso`.
No consumer needs an SDK type, so a fake or replacement driver can satisfy the contract without importing Turso.

The adapter accepts the database URL and token as separate in-memory values from its caller.
It never reads environment variables and never places the token in a DSN or URL.
It rejects empty caller-supplied endpoints, URL user information, queries, fragments, unsupported schemes, remote cleartext HTTP, and cleartext loopback HTTP carrying a token before constructing the driver.
The `turso` scheme is normalized to HTTPS.
Caller-supplied plain HTTP is limited to a literal IPv4 or IPv6 loopback address with no token for credential-free protocol tests.
These initial endpoint checks do not constrain a later protocol-provided `base_url`, including its scheme or authority.

The handle gives each ping an adapter-owned deadline no longer than 30 seconds, preserves a shorter caller deadline, and replaces every upstream ping diagnostic with a fixed safe category.
Close is idempotent and replaces a returned upstream close diagnostic with a fixed safe category.
The driver can still block inside transaction completion or stream close because its internal background contexts and private HTTP client are not controlled by the adapter.
That limitation is accepted, not fixed.

The adapter remains unreachable from the command graph, configuration loader, capability registry, service startup, health endpoints, Gmail, OAuth, and MCP.

## Known accepted risks

[The known-risk register](../known-risks.md) is normative for this decision.
It records the exact affected version, containment available in this inert adapter, missing upstream controls, revisit triggers, and closure criteria.

The accepted unresolved risks are:

- `TURSO-001`: a protocol-provided `base_url` can change scheme or authority before a later bearer-bearing request, including downgrading HTTPS to cleartext HTTP.
- `TURSO-002`: valid remote error text can be reflected raw by the driver.
- `TURSO-003`: commit, rollback, and stream close use internal background contexts and can outlive caller cancellation.
- `TURSO-004`: the driver owns a private HTTP client without an injectable redirect, transport, or timeout policy.
- `TURSO-005`: successful pipeline bodies, cursor lines, accumulated rows, and individual values lack repository-owned total limits.

No persistence feature may describe these risks as remediated while the selected driver retains the behavior.

## Alternatives considered

### Keep storage blocked

Keeping ADR 0003 as the final decision would avoid the accepted risk but would not meet the owner's requirement to continue with Turso.
The owner chose visible risk acceptance plus a replaceable boundary.

### Use `tursogo` local and Cloud sync

The current documentation recommends `tursogo` for local databases and explicit push and pull synchronization.
That would change the first-release architecture from direct remote canonical state to a local database, local durability, conflict, checkpoint, bootstrap, and recovery model.
This issue does not approve that larger architecture.

### Use `libsql-client-go`

The current documentation assigns `libsql-client-go` to remote legacy libSQL databases, not new databases using the Turso rewrite.
It also exposes similar authority, diagnostic, cancellation, and transport-control problems.
It is not selected.

### Use `go-libsql`

`go-libsql` targets the libSQL engine and embedded-replica use cases, requires CGO, and introduces native libraries.
Those properties do not match the selected Turso Database engine or the release build contract.

### Maintain a fork or protocol proxy

A fork or proxy could add owned transport, authority, response, and cancellation controls.
Either option would create a security-critical implementation and maintenance boundary.
It remains a possible closure path for the accepted risks but requires its own approved issue and ADR.

## Dependency and supply-chain review

- Module: `turso.tech/database/tursogo-serverless`.
- Version: `v0.0.0-20260817122138-24adc316cdc4`.
- Source repository: `https://github.com/tursodatabase/turso`.
- Source subdirectory: `serverless/go`.
- Source commit: `24adc316cdc4ebf93d90b94dbfda727195540497`.
- Module checksum: `h1:Fnxwfn492a+9kTegF2G7QUT1aF0Vfjz0dMrNO+HmthA=`.
- Module-file checksum: `h1:KWrz0BzLKiXUkLmM5HXyr/gWA8ySNZexfW0NV0GGk0A=`.
- Declared Go version: 1.24.0.
- Direct transitive module graph: none because the selected module declares no required modules.
- Runtime implementation graph: Go standard library packages only.
- License: MIT, compatible with InboxGate, with the upstream notice retained in `THIRD_PARTY_NOTICES.md`.
- Advisory review: `govulncheck`, the OSV API, and the GitHub Advisory Database found no published applicable advisory on 2026-08-17.
- Maintenance status: the package is maintained in Turso's active official repository, is documented as the remote client for new Turso Databases, and is available only as an untagged pseudo-version at this decision point.
- Removal plan: replace the constructor inside `internal/storage/turso`, retain the repository-owned `internal/storage` contract where compatible, remove the module and its checksums, update the notice and risk register, and rerun all storage contract tests and release-target builds.

The absence of a published advisory does not reduce the impact of the source behaviors recorded in the risk register.

## Security and privacy impact

This change opens a new code-level external-request boundary but does not activate it from the product runtime.
URL policy prevents a caller from putting credentials, queries, or fragments into the endpoint and limits cleartext transport to credential-free literal-loopback tests.
The adapter maps ping and close failures to fixed categories without returning raw SDK text.
Tests use synthetic values only and do not contact Turso Cloud.

The adapter cannot prevent the SDK's server-controlled scheme or authority update, including HTTPS-to-HTTP downgrade, change its redirect policy, impose total successful-response limits, or cancel its internal transaction and close contexts.
Those limitations remain accepted risks.

## Consequences

The architecture gate that prevented adding a Turso connection boundary is resolved for this exact inert adapter.
The next storage issue may design append-only migrations against the repository-owned contract, but it must not silently broaden the accepted risk or activate production credentials.
Runtime activation, production migration, and live database access still require separate approved work and explicit owner authorization.

Any driver upgrade must reopen the dependency and risk review even when the module path remains unchanged.
Any use beyond open, ping, and close must begin with a failing test and document how accepted upstream diagnostics, cancellation, replay, and response bounds are contained at that new call site.

## Validation

- Capture the missing adapter as a failing test before adding production code.
- Prove a fake replacement implements the consumer contract without importing the SDK.
- Prove URL and token separation at the private driver-construction boundary.
- Prove unsafe endpoints are rejected before driver construction without reflecting caller input.
- Prove adapter-owned and caller-owned ping cancellation with fixed diagnostics.
- Prove close idempotency and fixed returned diagnostics.
- Exercise the exact SDK against a credential-free literal-loopback SQL over HTTP server.
- Verify the exact module origin, commit, checksums, graph, license, and advisory scan.
- Run focused normal and race tests, the canonical repository check, `git diff --check`, and CGO-disabled compilation for every release target.
