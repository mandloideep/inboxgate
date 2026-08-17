# InboxGate

InboxGate is a small Go service that keeps high-volume email behind a deterministic review gate before an AI agent sees it.
The first release will connect multiple Gmail and Google Workspace accounts with read-only access and expose a bounded MCP surface to Hermes.

The repository currently contains the contributor foundation, a minimal command-line binary, and strict configuration schema v1 validation.
Email synchronization, persistence, MCP, OAuth, and deployment are intentionally not implemented yet.

## Quick start

InboxGate requires Go 1.26.6.

```sh
make check
go run ./cmd/inboxgate version
go run ./cmd/inboxgate help
go run ./cmd/inboxgate --config config.example.yaml config validate
go run ./cmd/inboxgate --config config.example.yaml config effective
```

Development builds print `inboxgate dev`.
Release builds print the canonical version and full source commit.
The validation command checks strict configuration schema v1 without credentials or network access.
The effective command prints the complete normalized policy and field provenance without reading named secret values or exposing the selected path.
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

## Contributing and support

See [CONTRIBUTING.md](CONTRIBUTING.md) for the issue-first workflow and required checks.
Use [SUPPORT.md](SUPPORT.md) for help and [SECURITY.md](SECURITY.md) for private vulnerability reporting.
Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Release operators and consumers should follow [docs/releases.md](docs/releases.md) for publication gates, checksums, and provenance verification.

## License

InboxGate is available under the [MIT License](LICENSE).
