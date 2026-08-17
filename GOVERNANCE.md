# Governance

InboxGate currently uses a maintainer-led governance model.
Deep Mandloi is the project maintainer and final decision maker until governance is expanded.

## Decision making

Product and architecture changes begin with a public issue.
Contributors should seek rough consensus through evidence, tests, and clear tradeoffs.
The maintainer resolves decisions that remain contested and records material architecture choices in `docs/adr/`.

Security, privacy, data-loss prevention, robustness, simplicity, scalability, and long-term maintainability take precedence over development cost.

## Changes

All code changes use pull requests and the checks described in [docs/development-workflow.md](docs/development-workflow.md).
One focused implementation pull request may be active at a time.
The maintainer may appoint additional maintainers after sustained, trustworthy contributions.

## Releases

Releases are deliberate maintainer actions from a validated `main` branch.
Release notes are generated from merged pull requests.
The project does not maintain a handwritten `CHANGELOG.md`.
