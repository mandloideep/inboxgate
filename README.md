# InboxGate

InboxGate is a small Go service that keeps high-volume email behind a deterministic review gate before an AI agent sees it.
The first release will connect multiple Gmail and Google Workspace accounts with read-only access and expose a bounded MCP surface to Hermes.

The repository currently contains the contributor foundation, a minimal command-line binary, strict configuration schema v1 validation, a typed capability registry, bounded process-health serving, and one authenticated stateless MCP endpoint.
Local configuration inspection, capability inspection, liveness, process readiness, structured runtime logging, graceful shutdown, local service preflight, authenticated `system_capabilities` inspection, gated account-status inspection, and dual-gated candidate inspection are implemented.
A replaceable Turso adapter with a provenance-pinned maintained fork for bounded stream close, embedded append-only migrations, minimum Gmail account identity and synchronization-cursor persistence, versioned authenticated encryption, a one-shot Gmail OAuth enrollment command, an inert bounded Gmail current-discovery use case, an inert deterministic persisted gate, and inert bounded candidate-content extraction are present with remaining driver behavior tracked in the [known-risk register](docs/known-risks.md).
Credential persistence stores only validated ciphertext envelopes and is covered by the same credential-free literal-loopback restriction as migrations and account-cursor persistence.
Versioned account lifecycle state supports bounded listing, pause, resume, typed reauthorization markers, enrollment activation, and staged provider revocation with exact local credential deletion.
The `account add` command resolves its selected Google, encryption, and database environment values and reaches OAuth, cryptobox, and credential-free literal-loopback Turso persistence.
The `account list`, `account pause`, and `account resume` commands resolve only selected database environment values, while `account revoke` resolves the selected encryption key only after winning a durable revoked-attempting claim and makes at most one bounded fixed-authority provider request.
The doctor, configuration inspection, capability inspection, and MCP-disabled health service remain inert and do not resolve those values.
Enabled `serve` validates the environment variable selected by `mcp.bearer_token_env` before bind and always exposes MCP `2026-07-28` discovery, tools/list, and `system_capabilities` on the exact configured private path.
When `mcp.enable_operator_tools` is also true, `serve` additionally requires credential-free literal-loopback storage and exposes only the bounded read-only `accounts_list` and `mail_sync_status` tools.
The current-discovery use case reconciles storage before provider work, refreshes one access token once, reads at most ten fixed Gmail history pages, fetches body-excluding projected metadata for at most 5,000 unique messages, and advances the exact cursor only with canonical message promotion.
It treats stale history separately from authorization failure, omits vanished messages, applies four-attempt bounded retry rules only to documented transient failures, and never fetches message bodies or attachment bytes.
It remains credential-free and disconnected from commands, service startup, health, capabilities, scheduling, MCP, remote Turso, and every executable runtime path.
The gate classifies canonical metadata with one versioned fixed-precedence policy, persists a closed outcome and sorted reason vocabulary through exact compare-and-swap, and reconciles uncertain writes without replay.
It remains credential-free and disconnected from executable Gmail polling, commands, scheduling, service startup, health, capabilities, MCP, and remote Turso.
The candidate-content extractor proves an active lifecycle and current candidate decision before one fixed read-only Gmail content request, prefers one inline plain-text part over one inline HTML part, excludes attachments, canonicalizes one UTF-8 excerpt, and persists it through an exact source-bound compare-and-swap.
Every excerpt is bounded by `gmail.body_excerpt_bytes`, explicitly typed as `untrusted_email`, and disconnected from commands, scheduling, service startup, health, capabilities, MCP, remote Turso, and live credentials.
The validated `retention.excerpt_days` setting remains policy only because this inert slice does not schedule or perform content deletion.
Executable Gmail polling, review writes through MCP, live OAuth approval, remote database activation, and deployment are intentionally not implemented yet.

## Quick start

InboxGate requires Go 1.26.6.

```sh
make check
go run ./cmd/inboxgate version
go run ./cmd/inboxgate help
go run ./cmd/inboxgate --config config.example.yaml config validate
go run ./cmd/inboxgate --config config.example.yaml config effective
go run ./cmd/inboxgate --config config.example.yaml capabilities
go run ./cmd/inboxgate --config config.example.yaml doctor
go run ./cmd/inboxgate --config config.example.yaml account add --help
go run ./cmd/inboxgate --config config.example.yaml account list --help
```

Development builds print `inboxgate dev`.
Release builds print the canonical version and full source commit.
The validation command checks strict configuration schema v1 without credentials or network access.
The effective command prints the complete normalized policy and field provenance without reading named secret values or exposing the selected path.
The capabilities command prints compile-time implementation, validated configuration, effective enablement, prerequisite names, migration requirements, and security classification as deterministic JSON.
Environment-variable names in capability output may be sensitive even though their values are never read.
The doctor command validates local service construction without opening a listener.
The serve command always exposes fixed liveness and process-readiness probes.
When `mcp.enabled` is true, it additionally requires the selected MCP token before bind and registers the exact authenticated MCP route with `system_capabilities`.
When `mcp.enable_operator_tools` is also true, the same route adds tenant-wide `accounts_list` and `mail_sync_status` for the one owner-approved Hermes principal after credential-free literal-loopback storage validation.
The service must bind only to an approved private interface or private reverse-proxy path and this implementation is not deployment authorization.
See the [configuration guide](docs/configuration.md) and [complete example](config.example.yaml).

## Product boundaries

- Gmail access is read-only.
- InboxGate does not send, delete, archive, label, forward, or mark email as read.
- InboxGate is a deterministic data service, not an autonomous agent.
- Hermes reaches InboxGate through MCP only.
- InboxGate does not call Vikunja directly.
- Secrets and real email content never belong in source, fixtures, logs, or documentation.

Read the [product specification](docs/product-specification.md) and [threat model](docs/threat-model.md) before proposing product behavior.

## Project status

InboxGate is pre-release software under active development.
The roadmap is delivered as one focused GitHub issue and pull request at a time.
Future web work may use `web/apps/console`, `web/apps/site`, and `web/packages/ui`, but those applications are not approved or created yet.
Owners should use the [readiness and blocker guide](docs/owner-readiness.md) before preparing provider access, runtime secrets, private deployment, or a manual release.

## Contributing and support

See [CONTRIBUTING.md](CONTRIBUTING.md) for the issue-first workflow and required checks.
Use [SUPPORT.md](SUPPORT.md) for help and [SECURITY.md](SECURITY.md) for private vulnerability reporting.
Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Release operators and consumers should follow [docs/releases.md](docs/releases.md) for publication gates, checksums, and provenance verification.

## License

InboxGate is available under the [MIT License](LICENSE).
# Read-only candidate inspection

When both `mcp.enabled` and `capabilities.mail.review_read` are true, InboxGate exposes `mail_list_review_candidates` and `mail_get_gate_reason` to one owner-approved bearer principal with tenant-wide sensitive-read authority.
Account filters narrow results but never authorize an account.
Every email-derived value is marked or treated as `untrusted_email` and cannot authorize another action.
Candidate excerpts are explicitly excluded from both tools.
The source performs fixed bounded reads and does not close `TURSO-005`.
