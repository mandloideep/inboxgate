# ADR 0016: Own the bounded Turso stream-close lifecycle

- Status: Accepted
- Date: 2026-08-19
- Issue: #41
- Owners: @mandloideep
- Supersedes: the stream-close risk acceptance in [ADR 0004](0004-turso-serverless-adapter.md) only

## Context and need

Issue #40 cannot truthfully construct and close its bounded account-status source within the server shutdown budget while the selected Turso driver owns stream close.
The exact selected `turso.tech/database/tursogo-serverless` source calls the close pipeline with `context.Background()` through a private `http.Client` that has no timeout or injection point.
The driver discards every stream-close result.
The current adapter therefore cannot cancel a stalled close request, propagate its failure, join it before return, or truthfully report that storage has stopped.

The tests-only red commit `091374ac1ac7573404758122682b0bafa1a92f8f` reproduces the end-user shutdown failure on clean `main` before this decision or any production behavior.
A credential-free synthetic loopback server holds the fixed stream-close response beyond the adapter's 20 millisecond cleanup deadline.
`storage.Handle.Close` remains blocked until the server releases the response and then incorrectly returns success.
The same red matrix proves sequential close of two idle streams, discarded transport and protocol failures, missing context-aware connector shutdown, unbounded pool-eviction close, and absent local-fork provenance and release metadata.

Immediately before this proposal, the official Go module proxy still reported `v0.0.0-20260819191607-82feb785ae85` as latest.
That version resolves to official source commit `82feb785ae85527edcb617b219d6dd5625833bf8`, dated 2026-08-19T19:16:07Z.
The complete latest module directory is byte-identical to selected `v0.0.0-20260817122138-24adc316cdc4`, so a version-only upgrade does not change the affected close implementation.
Both exact source commits have valid GitHub commit verification.

The public wrapper cannot reach the driver's private session, baton, or HTTP client.
The standard library cannot impose a caller context on a dependency that creates `context.Background()` internally.
A focused maintained fork is the smallest boundary that can make this lifecycle truthful without replacing the selected storage engine or protocol.

## Decision

InboxGate will maintain a repository-local fork of the exact selected official module under `third_party/tursogo-serverless` with the unchanged module path `turso.tech/database/tursogo-serverless`.
The root module will retain the exact selected version requirement as provenance and add one relative replacement to `./third_party/tursogo-serverless`.
The replacement adds no module, CGO, native library, subprocess, listener, proxy, generator download, or network service.

The fork will copy the exact selected module's `driver.go`, `session.go`, `protocol.go`, `go.mod`, `README.md`, and upstream tests.
It will also retain the upstream root `LICENSE.md` as local `LICENSE`, add one local close contract test, and add one machine-readable provenance manifest.
No copied file other than `driver.go` and `session.go` may receive a semantic change.
The manifest will record the module path, selected version, source commit, module and module-file checksums, deterministic upstream tree hash, local path, every upstream and local SHA-256, and the exact modified-file allowlist.

### Accepted nonsemantic punctuation normalization

The owner accepted one provenance amendment after the exact upstream copy revealed four prohibited em dash characters in copied documentation and test comments.
The local fork will replace only those four punctuation characters with plain hyphens and will record the normalization separately from semantic production modifications.
`README.md` changes from upstream SHA-256 `372c9e177a79aa9df94a4d31a4b6f70dfc644d59ecfe6e2d5012a4c81e276c28` to local SHA-256 `9288fad74312e0ea2cb617286b099d249671c75ffdcf87263c6b42ee8d2cdcb6`.
`encryption_header_test.go` changes from upstream SHA-256 `8ca1300bb14acea96fbf307315d2a605b5919ad0626b99835094b821df1ef997` to local SHA-256 `04e6341e97807c3da3e82378b6df473b781fe6117f2fba5445c7f69bc449f390`.
The manifest `normalized_files` allowlist will contain exactly those two paths.
The semantic `modified_files` allowlist remains exactly `driver.go` and `session.go`.
No executable token, assertion, fixture value, protocol behavior, or test behavior changes through this normalization.

### Accepted independent-review evidence amendment

Independent correctness, security, and test review required additional evidence without changing the accepted dependency, capability boundary, or two-file semantic allowlist.
The review-red commit is `f38eb7ddd82f2c87a82b05be5c8586ccdda8663e`.
It requires the nested fork fixture to bound and validate the exact close body before blocking, register cleanup-only release paths before server shutdown, positively observe request-context cancellation, preserve the exact terminal error through later database close, and prove no replay.
It also requires 32 synchronized connector close callers plus a sequential repeat to converge on one terminal result, exact acceptance of the ten-second maximum, strict independently pinned provenance evidence, and mandatory nested-module tidy, verify, vet, test, and race gates.
Nested fork tests must fail closed before running if either `TURSO_DATABASE_URL` or `TURSO_AUTH_TOKEN` is present, and every repository-owned invocation must explicitly remove both variables.

Review also found that calling `CloseIdleConnections` on a client with a nil transport can mutate the process-global default transport.
Within the accepted `session.go` semantic scope, every session will instead construct and retain its own standard-library transport using the same proxy, dial, HTTP/2, idle, TLS-handshake, and expect-continue defaults previously inherited from `http.DefaultTransport`.
Stream close will close idle connections only on that owned transport.
This does not add transport injection, redirect control, proxy selection, a new endpoint, or arbitrary network authority, and it does not close `TURSO-004`.

### Driver close ownership

`driver.go` will add an explicit connector constructor that accepts a positive bounded fallback close duration.
The existing `NewConnector` will remain source-compatible and will use a fixed two-second fallback close duration.
The InboxGate adapter will use the explicit constructor with its already validated `Options.CleanupTimeout`, whose default is two seconds and maximum is ten seconds.

Each connector will register every physical connection it creates and remove it only after that connection reaches its terminal local close state.
Connector shutdown will atomically stop admission before taking a connection snapshot.
Every later `Connect` call will fail with the existing `ErrTursoConnClosed` sentinel and create no connection or request.

The connector will expose `CloseContext(context.Context) error` as the only new lifecycle authority used by InboxGate.
It will close registered connections with at most two joined workers under the same caller-owned context.
It will wait for every started worker before returning and will preserve one terminal connector result for repeated callers.
It will not return while a close request or close worker remains live.

Each driver connection will expose idempotent `CloseContext(context.Context) error` internally to the connector.
The existing `driver.Conn.Close` method will create one context using the configured bounded fallback and delegate to that same terminal operation.
Repeated or concurrent closes will wait for or reuse the first terminal result and will not send another request.
This bounds `database/sql` pool eviction even though `driver.Conn.Close` cannot accept a caller context.

`session.go` will change only session transport ownership and `close()` to `close(context.Context) error`.
Each session will use an owned standard-library transport with the same policy defaults previously inherited from the process-global default transport.
It will pass that context to the existing single fixed close pipeline, validate the one expected close result, return transport, status, decoding, or protocol failure, reset the stream exactly once, and close idle transport connections before returning.
It will never replay a failed or uncertain close.
It will send no request when the session has no baton.

### Adapter close ordering

`internal/storage/turso/adapter.go` will retain the connector next to its `sql.DB` without exposing either beyond the adapter.
The database will explicitly retain at most two idle physical connections.
`storage.Handle.Close` will preserve its existing no-argument and idempotent public contract.
Its first caller will create one context from the validated cleanup timeout, call connector `CloseContext`, then call `sql.DB.Close`, then close idle transport resources through the connector-owned lifecycle.
The connector close runs before `sql.DB.Close`, so the later database close is local and cannot send a second stream-close request.
Every connector or database failure maps only to fixed `turso.ErrCloseFailed` without preserving remote text.
Concurrent handle callers will wait for the same terminal operation and receive the same fixed result.

Callers must stop admission and drain active storage operations before calling `Handle.Close`.
This decision does not add support for close racing with an active query.
After the drain precondition, `database/sql` can retain at most two idle registered connections, and the connector's fixed two-worker bound closes both under one shared deadline.

## Exact behavior and capability boundary

A handle that never acquired a physical connection sends no close request.
A physical connection with no baton sends no close request.
Each open stream sends exactly one existing protocol close request containing only the fixed `close` request type and its internal baton.
No user or operator can supply SQL, URL, path, header, body, baton, retry, pagination, or concurrency input to this request.

Successful close returns nil only after every physical connection and close request is terminal.
Deadline, caller cancellation, transport failure, malformed response, non-success status, dropped response body, remote protocol error, or unexpected response shape cancels or completes the underlying request, closes local resources, and returns failure.
The adapter exposes only fixed `turso.ErrCloseFailed` for every such failure.
Remote diagnostics, URLs, tokens, SQL, batons, account data, and response bodies cannot cross the adapter.

This decision changes no domain or application contract, SQL statement, migration, account row, Gmail request, OAuth behavior, MCP tool, server route, configuration key, secret name, operator command, scheduler, deployment, or release activation.
It adds no raw SQL, arbitrary Turso request, generic URL fetch, shell execution, provider framework, plugin system, or mutation authority.
Credential-free literal-loopback tests remain the only permitted runtime validation.
Remote Turso, database tokens, live data, Gmail, deployment, and release remain prohibited without later explicit owner approval.

## Alternatives considered

### Upgrade to the official latest version

This was rejected because the complete latest module directory is byte-identical to the selected source and retains the same background close context, private no-timeout client, discarded error, and missing connector shutdown.

### Return from an outer timeout goroutine

This was rejected because it abandons a live HTTP request, goroutine, stream, and physical connection after reporting shutdown completion.
That result is untruthful and violates the issue stop condition.

### Override the process default transport

This was rejected because it mutates global HTTP behavior, does not supply the required caller context or connector join, and depends on an upstream implementation detail.

### Use reflection, `unsafe`, or `go:linkname`

These were rejected because they cross private dependency state without a stable contract and would make a security-critical shutdown boundary dependent on runtime layout or linker behavior.

### Add an in-process reverse proxy

This was rejected because it adds another listener, HTTP authority, request forwarding boundary, lifecycle, and potential arbitrary URL surface without fixing driver ownership directly.

### Make stream close a no-op

This was rejected because an open transaction must be rolled back server-side and local omission would hide uncertain server state rather than close it.

### Isolate the driver in another process

This was rejected because process isolation adds a subprocess protocol, supervision, packaging, termination, and recovery boundary far larger than the two-file lifecycle correction.

### Adopt `tursogo`

This was rejected because `tursogo` is a local database with optional Cloud push and pull, which would replace the direct remote canonical-state architecture with local durability and synchronization semantics.

### Adopt `libsql-client-go`

This was rejected because it targets the legacy libSQL engine, exposes similar HTTP lifecycle risks, and does not match the selected Turso Database engine contract.

### Adopt `go-libsql`

This was rejected because it targets libSQL and embedded replicas, requires CGO and native libraries, and breaks the six-target CGO-disabled release contract.

### Rewrite storage or the protocol client

This remains a future option for closing all accepted Turso risks, but it is broader than the single stream-close prerequisite blocking issue #40.

## Dependency and supply-chain review

- Direct module: `turso.tech/database/tursogo-serverless`.
- Selected version: `v0.0.0-20260817122138-24adc316cdc4`.
- Selected source commit: `24adc316cdc4ebf93d90b94dbfda727195540497`.
- Selected source repository: `https://github.com/tursodatabase/turso`.
- Selected source subdirectory: `serverless/go`.
- Selected module checksum: `h1:Fnxwfn492a+9kTegF2G7QUT1aF0Vfjz0dMrNO+HmthA=`.
- Selected module-file checksum: `h1:KWrz0BzLKiXUkLmM5HXyr/gWA8ySNZexfW0NV0GGk0A=`.
- Selected module tree evidence SHA-256: `4ce5b8f1db237ec167eb7ca26bf9383e2971bdc6432ecead3441abc1a053e40c` over sorted relative-path file digests.
- Official latest at proposal: `v0.0.0-20260819191607-82feb785ae85`.
- Latest source commit: `82feb785ae85527edcb617b219d6dd5625833bf8`.
- Latest module checksum: `h1:r4cpXA43B7hTklLAsCRGcrbn+3/lQKpuKDKrkiok/KQ=`.
- Latest module-file checksum: `h1:KWrz0BzLKiXUkLmM5HXyr/gWA8ySNZexfW0NV0GGk0A=`.
- Latest comparison: byte-identical to the selected complete module directory.
- Local replacement: `./third_party/tursogo-serverless` with unchanged module path.
- Declared Go version: 1.24.0.
- Transitive module impact: zero upstream required modules and no change to InboxGate's 16-module selected graph including the root module.
- Root checksum-file impact: `go mod tidy` removes the two upstream Turso checksum lines because local replacements are not authenticated through `go.sum`, so the accepted proxy checksums remain pinned in this ADR, the provenance manifest, and release validation instead.
- Runtime graph impact: Go standard library only for this driver.
- CGO and native impact: none.
- License: MIT, compatible with InboxGate's MIT distribution.
- Upstream license source: root `LICENSE.md` at the selected commit with SHA-256 `b646f9ee8bcaf87e8de75153b9df7a2861c7ac445c87e741768b3c2bccf47bc5`.
- Notice obligation: retain the complete MIT text and identify InboxGate's modified local source, upstream version, source commit, local path, and modified files in `THIRD_PARTY_NOTICES.md`.
- Advisory review: pinned `govulncheck v1.1.4` scanned the selected package graph and Go 1.26.6 immediately before proposal and found no vulnerability.
- Maintenance status: both selected and latest commits are validly verified commits in Turso's active official repository, and the package remains published only as pseudo-versions.

The absence of a published advisory does not replace the source review or reduce the directly reproduced close risk.
Any new reachable unresolved advisory, module graph change, license change, provenance mismatch, copied-source drift, or semantic modification outside `driver.go` and `session.go` blocks merge and requires an amended accepted decision.

## Synchronization, review, removal, and rollback

Every future upstream update must compare the complete official `serverless/go` module against the local baseline and the two-file patch.
The provenance manifest and all local hashes must change in the same approved dependency issue.
Correctness, security, and test reviewers must independently inspect the complete local fork, the exact two-file semantic diff, the manifest, notice, module graph, binary metadata, SBOM shape, and all close tests.

The preferred removal path is an immutable official release that exposes equivalent context-aware, error-propagating, cancelable, joined connector shutdown and passes the complete red matrix without a local semantic patch.
Removal would delete the local fork only through a separate deletion-aware issue and owner execution, remove the relative replacement, restore exact upstream build metadata and SBOM expectations, update notices and risks, and run every storage and release contract.

Rollback of this issue restores the prior exact upstream module resolution and adapter close behavior, then keeps issue #40 runtime wiring blocked.
No schema, row, provider, credential, remote service, or deployed runtime requires rollback.

## Security and privacy impact

This decision moves a small security-critical SQL-over-HTTP lifecycle boundary under repository maintenance.
That increases source-review, synchronization, advisory, notice, and release-metadata responsibility.
It does not expand the SQL, URL, credential, Gmail, MCP, shell, provider, or network capability surface.

Caller-owned cancellation now reaches every stream-close HTTP request.
Connector registration and joined shutdown make local resource ownership explicit and prevent shutdown from returning while a close request remains live.
Fixed adapter error mapping continues to prevent untrusted remote diagnostics from crossing the storage boundary.
The fixed two-worker limit prevents unbounded shutdown fanout.

`TURSO-003` becomes partially contained for stream close only.
Explicit transaction commit and rollback still create background-context requests and remain open.
`TURSO-001` remains open for protocol-controlled authority changes.
`TURSO-002` remains open for driver diagnostics outside adapter sanitization.
`TURSO-004` remains open for redirect and general client policy because owned transport lifetime does not provide policy injection or fail-closed redirect behavior.
`TURSO-005` remains open for successful-response allocation bounds.
No persistence feature may describe those remaining risks as remediated.

## Consequences

Issue #40 can resume only after this fork passes credential-free integration that stops admission, cancels and drains MCP work, closes the account source, and finishes under the existing single server shutdown deadline.
The existing `storage.Handle` contract remains stable and replacement-friendly.
Pool eviction and application shutdown share one driver close implementation instead of diverging.
Close success becomes truthful, and close failure becomes bounded and fixed at the adapter boundary.

InboxGate assumes long-term responsibility for a minimal local fork until equivalent upstream behavior exists.
The relative module replacement appears in Go build metadata and changes the pinned Syft SBOM representation, so release validation must recognize only this exact reviewed replacement and its upstream provenance.

## Stop condition

Implementation must stop before local source or production behavior if official source cannot be legally or reproducibly copied, the graph adds a dependency or native code, the exact two-file semantic patch cannot cancel every close request, any worker can outlive the shared context, any close returns while work remains live, or existing storage and release contracts regress.
Implementation must also stop rather than widen scope if it requires semantic changes to `protocol.go`, SQL execution, transaction methods, parsing, encoding, decoding, request paths, global state, reflection, unsafe access, a proxy, or arbitrary protocol authority.

If the stop condition is triggered, issue #40 remains blocked and a larger storage architecture replacement must be planned.

## Validation

The tests-only red commit is `091374ac1ac7573404758122682b0bafa1a92f8f`.
The combined focused red command exited 1 before this ADR because current close exceeded the owned deadline, closed two streams sequentially, discarded every close failure, exposed no context-aware connector shutdown, left pool eviction unbounded, and lacked the approved local source, manifest, notice, replacement, and release metadata.

After acceptance, validation must prove:

- One stalled close returns fixed `ErrCloseFailed` within the adapter-owned deadline without a server release.
- The synthetic server observes propagated `request.Context().Done()` within a bounded scheduler allowance after local close completion.
- Active close requests and registered terminal connections are zero at return.
- Two idle streams close under one shared deadline with no timeout multiplication.
- Success sends exactly one fixed close request per stream.
- Never-connected and no-baton connections send no close request.
- Non-success status, malformed response, protocol error, dropped body, deadline, and cancellation remain bounded, fixed, non-sensitive, and unreplayed.
- Repeated and concurrent handle and connector closes are idempotent and race-free.
- Thirty-two synchronized direct connector close callers and one sequential repeat share one exact terminal result and one request.
- Connector shutdown rejects new connections.
- `sql.DB.Close` after connector shutdown is local and sends no second request.
- Pool-eviction `driver.Conn.Close` uses the configured bounded fallback.
- The exact ten-second constructor maximum is accepted and ten seconds plus one nanosecond is rejected.
- Each session owns its standard-library transport, close never mutates a substituted process-global transport, and no owned idle connection remains after close.
- Authorization is absent from every credential-free fixture.
- Nested fork tests fail closed before execution when either live Turso environment variable is present, and all required nested commands explicitly remove both variables.
- Copied source, semantic-diff allowlist, independently pinned upstream tree and per-file hashes, strictly decoded bounded provenance, MIT notice, module graph, binary replacement metadata, SBOM representation, and all six CGO-disabled builds are exact.
- Existing storage, migration, lifecycle, discovery, gate, candidate-content, MCP, and release contracts remain unchanged.

Required commands include 100 focused repetitions, 20 race repetitions, local fork normal and race tests, all storage tests, all repository tests, module tidy and verification, exact module and build-information inspection, vulnerability scanning, `make check`, six release builds, diff checks, protected-file checks, secret and identifier scans, forbidden-authority scans, em dash scans, coauthor scans, and deletion audits.

## Owner action

OWNER ACTION: explicit acceptance of this proposed ADR is required before adding `third_party/tursogo-serverless`, changing `go.mod`, changing notices, or adding production behavior.
No Turso token, endpoint, database name, organization, account identifier, Gmail credential, production secret, deployment approval, or release approval is required or authorized for implementation and credential-free validation.
