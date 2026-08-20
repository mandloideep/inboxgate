# ADR 0015: Bound MCP account-status disclosure to one owner-approved principal

- Status: Accepted
- Date: 2026-08-19
- Issue: #40
- Owners: @mandloideep

## Context and need

InboxGate's authenticated MCP endpoint exposes the compiled capability registry, but the owner-approved Hermes service identity cannot discover enrolled account identities or determine whether current synchronization and backfill are available.
The operator account list already reads one bounded lifecycle and cursor-presence summary, but MCP must not parse command output or receive a mutation-capable storage handle.
InboxGate does not persist display names, email addresses, last synchronization times, stale-cursor state, synchronization errors, backfill checkpoints, or backfill progress.
This decision must expose those unavailable facts explicitly without inventing state or treating cursor presence as freshness or success.

Account identifiers and lifecycle state are sensitive tenant-wide operational data.
The v0.1 deployment has one human owner and one owner-approved Hermes bearer principal.
A broader principal, tenant, delegation, role, or account-selection model would require a different authorization design.

## Decision

InboxGate will add one typed read-only account-status application service and two read-only MCP tools named `accounts_list` and `mail_sync_status`.
The application service accepts only a narrow source with the existing bounded `ListAccounts(context.Context)` operation and one defensive copy of the typed capability registry.
It receives no `storage.Handle`, database handle, SQL, transaction callback, lifecycle mutation, provider credential operation, Gmail operation, synchronization executor, or backfill executor.
Each successful tool call makes exactly one account-list query and performs no retry or per-account query.

The tools are registered only when both `mcp.enabled` and `mcp.enable_operator_tools` are true.
The existing `system_capabilities` tool remains registered whenever MCP is enabled.
When operator tools are disabled, the new names use the existing fixed unknown-tool result and no database selector, endpoint value, token value, adapter, handle, or source is resolved or constructed.
When MCP is disabled, no MCP or database selector is resolved.

The existing bearer represents the single owner-approved Hermes service identity.
Explicit operator enablement authorizes that identity to read the bounded status snapshot for every enrolled account in this single-owner deployment.
Neither tool accepts an account identifier, allowlist, tenant, user, principal, role, filter, pagination value, cursor, or any other argument.
This removes caller-controlled account enumeration and prevents input from broadening the principal's authority.
A future multi-user, multi-principal, delegated-account, or role-based deployment must replace this tenant-wide decision before activation.

`tools/list` advertises exactly `accounts_list`, `mail_sync_status`, and `system_capabilities` in bytewise name order when operator tools are enabled.
Both new tools use an object input schema with zero properties and `additionalProperties: false`.
Both tools declare read-only, idempotent, non-destructive, and closed-world annotations.
The existing authentication, route, protocol, media, Host, browser-origin, header, body, JSON-structure, concurrency, five-second application deadline, response-limit, audit, and shutdown controls remain outer controls for every call.

### `accounts_list` output

The structured output fields are `output_version` followed by `accounts`.
Each account contains `account_id`, `provider`, `state`, `state_version`, `reauthorization_reason`, and `revocation_status` in that order.
The output contains zero through 100 accounts sorted by bytewise account identifier.
Account identifiers are exact 32-character lowercase hexadecimal opaque identifiers.
The provider is exactly `gmail`.
Lifecycle state, version, reauthorization reason, and revocation status use the existing closed storage vocabularies and valid cross-field shapes.

The output excludes provider subject, email address, display name, credential presence, credential data, cursor presence, cursor value, Gmail identifier, message data, endpoint, hostname, URL, private path, and secret information.
InboxGate does not infer a display name or translate absence of a persisted fact into a negative claim.
More than 100 rows, duplicate or unsorted rows, malformed data, source failure, cancellation, deadline, or oversized complete output fails the call without partial output.

### `mail_sync_status` output

The structured output fields are `output_version` followed by `accounts`.
Each account contains `account_id`, `current_sync`, and `backfill` in that order.
The account snapshot and ordering are identical to `accounts_list`.

The `current_sync` object contains `implementation_status`, `configuration_status`, `enabled`, `execution_status`, `cursor_status`, `stale_status`, `last_success_at`, and `last_error_category` in that order.
The `backfill` object contains `implementation_status`, `configuration_status`, `enabled`, `execution_status`, `checkpoint_status`, and `progress` in that order.

Implementation, configuration, and enabled values come only from exact `gmail.current_sync` and `gmail.backfill` entries in `config.CapabilityRegistry`.
Missing, duplicate, malformed, or unexpectedly enabled required entries fail closed before a source query.
The application does not create a second capability truth model.

Cursor presence maps only to `initialized` or `uninitialized`.
An initialized cursor does not claim freshness, successful synchronization, connectivity, runnable synchronization, or a non-stale cursor.
Current execution is `not_available`, durable stale state is `not_persisted`, and last success and last error category are null because those facts are not persisted.
Backfill execution is `not_available`, checkpoint state is `not_persisted`, and progress is null because backfill is not implemented and has no durable checkpoint.
The history identifier is never exposed.

### Capability registry

The registry adds `system.account_status` with implementation status `implemented` and security classification `sensitive_read`.
Its configuration status is enabled only when both MCP and operator tools are enabled.
Its enabled value follows the existing derived rule.
Its required secret names are the bytewise-sorted configured database URL, database token, and MCP token environment-variable names.
Its required database migration is `0004_account_lifecycle.sql`.
No YAML key is added.
This decision does not mark `gmail.read`, `gmail.current_sync`, `gmail.backfill`, or `mail.review_read` implemented or enabled.

### Runtime and TURSO-003 stop condition

The only permitted runtime database endpoint for this issue is credential-free literal IPv4 or IPv6 loopback HTTP with an absent database token.
The endpoint must pass the existing bounded environment resolution, selector-separation, URL, token, and adapter checks before bind.
Construction performs no migration, ping, Gmail request, OAuth request, encryption operation, synchronization, backfill, or durable mutation.
Partial resources must close on construction failure.
Shutdown must stop admission, cancel and drain active MCP requests, and then close the source within the existing bounded shutdown budget.

Credential-free exact-driver evidence proves that a stalled `ListAccounts` request observes caller cancellation and returns one fixed sanitized failure without replay.
The same exact selected driver calls stream close with `context.Background()` through a private HTTP client with no timeout or transport injection.
The existing `TestDriverStreamCloseHasNoCallerControlledDeadline` regression proves that `storage.Handle.Close` remains blocked until a synthetic server releases the close response.
Returning from an outer timeout by abandoning that close in a goroutine would leak a live request and connection and is prohibited.

The runtime stop condition is therefore active at the time of this proposal.
Issue #40 must stop before production `serve` wiring unless a focused accepted storage-runtime prerequisite supplies a truthful bounded and cancelable close for this source.
Application and injected-handler design may be reviewed independently, but no executable path may resolve the database or construct the source while this condition remains open.
This is a prerequisite finding, not a claim that TURSO-003 is remediated.

## Alternatives considered

Parsing `account list` JSON was rejected because command output is an operator presentation format and would bypass the typed application and authorization boundary.

Passing `storage.Handle` or the lifecycle manager into MCP was rejected because either surface carries mutation, credential, provider, or broad persistence authority beyond the two reads.

Adding account selectors, pagination, or per-account authorization was rejected because the v0.1 owner has one approved principal and selector input would create an account-existence oracle without serving the current deployment.

Inferring synchronization health from cursor presence was rejected because a cursor can be old, invalid, disconnected, or unusable and no durable success or stale state exists.

Adding display names, timestamps, error history, stale state, checkpoints, or progress was rejected because those values are not persisted and this issue authorizes no migration.

Running unbounded driver close in a goroutine and returning on a timer was rejected because it would abandon live network work and make shutdown completion untruthful.

Activating remote Turso, bearer-bearing database access, live Gmail, or production credentials was rejected because those boundaries remain outside this credential-free implementation issue and require explicit owner approval.

## Dependency and supply-chain review

This decision adds no direct or transitive dependency and changes no selected version, checksum, notice, workflow, release tool, package-manager lockfile, or container image.
It reuses the exact accepted MCP SDK and Turso driver graphs recorded by ADR 0014 and ADR 0004.
No dependency ADR amendment is needed unless implementation changes the resolved module or version graph.

The selected Turso version still carries accepted risks TURSO-001 through TURSO-005.
This issue narrows runtime eligibility to credential-free literal-loopback storage, maps every source and decoding failure to a fixed category, preserves query cancellation, refuses live endpoints and tokens, and enforces semantic row and output bounds after driver buffering.
Those controls contain but do not close the accepted risks.

## Security and privacy impact

This decision would add authenticated read-only storage reachability and tenant-wide enumeration of opaque account identifiers and lifecycle state.
It adds no Gmail request, OAuth request, email content access, provider mutation, database mutation, raw SQL, arbitrary provider call, shell execution, URL fetching, direct Vikunja operation, public REST route, A2A surface, scheduler, synchronization execution, or backfill execution.

Authentication, protocol, and structural validation complete before the source is called.
Unauthorized, malformed, disabled, unknown-tool, and invalid-argument requests make zero storage calls.
Every source, decode, deadline, cancellation, and response-size failure maps to fixed JSON-RPC `-32603` without error data or upstream diagnostics.
Unknown tools retain the existing fixed method-not-found category.

Account identifiers, lifecycle state, cursor presence, registry state, and environment-variable names remain sensitive.
Audit events add only fixed operations `mcp.accounts_list` and `mcp.mail_sync_status` with the existing allowlisted fields.
Audits contain no account identifier, tool argument, body, header, Host, URL, endpoint, token state, cursor, provider value, source error, or response.
Runtime audit remains non-durable and is not approved for deployment until a later accepted issue provides approved collection, access, retention, and incident procedures.

The threat model must record tenant-wide authorization, account enumeration, lifecycle and cursor-presence disclosure, registry drift, storage error redaction, cancellation, close behavior, and audit retention.
The prompt-injection boundary is unchanged because no email content enters either output and no output can authorize a tool or mutation.

## Consequences

The application contract and MCP presentation remain deterministic, bounded, typed, defensive, and replaceable.
Unavailable durable facts are explicit instead of silently omitted or fabricated.
The one-principal authorization decision is simple and exact for v0.1 but cannot be reused for a broader tenancy model.

The current driver close behavior blocks production serve wiring under this issue's explicit stop rule.
A focused prerequisite must close that runtime lifecycle gap before the real-process success contract and full issue acceptance can pass.
Until then, the default one-tool MCP surface remains byte-compatible and no database value is resolved by `serve`.

## Rollback and removal

After eventual activation, setting `mcp.enable_operator_tools` to false removes both account-status tools and avoids all database resolution while leaving `system_capabilities` unchanged.
Setting `mcp.enabled` to false or redeploying the previously validated binary removes the complete MCP surface.
No stored data, schema, migration, or provider state requires rollback.

This issue deletes, renames, truncates, and replaces no pre-existing file.
Removing future account-status source, application, tests, or documentation requires a separate approved deletion-aware issue and owner action under `DELETION_REQUESTS.md`.

## Validation

The comprehensive tests-only red commit `0b3486982c3c4b58843b970f6731253c0c699d31` predates this ADR and all production behavior.
It covers the operator gate, exact inventory and schemas, authorization and structural precedence, zero through 101 accounts, ordering, malformed values, exact output, excluded sensitive fields, registry composition, unavailable facts, one source call, no retry, cancellation, deadline, response cap, defensive copies, audit operations, environment and endpoint policy, process construction, real-process loopback behavior, and absence of generic or mutation authority.

The focused credential-free exact-driver command is:

```text
GOCACHE=/private/tmp/inboxgate-issue40-red-go-cache go test -run 'TestLifecycleListAndLookupCancellationAreBoundedSanitizedAndNeverReplayed|TestDriverStreamCloseHasNoCallerControlledDeadline' -count=1 ./internal/storage/turso
```

It proves bounded canceled reads and reproduces the unbounded close property that activates the stop condition.

After the prerequisite is accepted and implemented, validation must include focused application, MCP, server, configuration, storage, and command tests, 50 repeated MCP runs, race runs, bounded fuzzing, all repository tests, module invariance, vulnerability review, `make check`, diff checks, all six CGO-disabled release builds, and the credential-free real-process loopback contract.
Validation must also confirm no workflow or release change, no migration or dependency change, no real identifier or secret, no forbidden authority, no em dash character, no coauthor trailer, and no deletion request.

## Owner action

OWNER ACTION: none for this decision, the focused storage prerequisite, implementation, review, merge, or credential-free validation.
Live database credentials, remote Turso, live Gmail, production secrets, Hermes activation, deployment, and release remain prohibited without their later explicit approvals.
