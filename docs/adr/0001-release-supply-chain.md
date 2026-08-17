# ADR 0001: Pin the release supply chain and keep packaging repository-owned

- Status: Accepted
- Date: 2026-08-16
- Issue: #4
- Owners: @mandloideep

## Context and need

InboxGate needs an owner-triggered way to publish binaries from one reviewed `main` commit without trusting a maintainer workstation.
The release path must cross-compile six targets, generate an SPDX SBOM, attach provenance, verify a remote draft, and publish an immutable release.
The Go standard library can build and package the artifacts, but it cannot call GitHub's authenticated release and attestation services or generate a standards-complete SBOM by itself.

The release workflow and its tools execute with supply-chain authority.
A floating Action or tool version could change code between review and release.

## Decision

Repository-owned Go code performs metadata validation, cross-compilation, build-information inspection, deterministic tar and ZIP creation, checksums, SBOM validation, and artifact-set validation.
The code uses only the Go standard library and adds no runtime module dependency.

The workflow uses the following exact immutable Action commits and tool versions:

- `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`, upstream v7.0.1, checks out the expected commit with credential persistence disabled.
- `actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`, upstream v7.0.0, installs Go 1.26.6 without an Action cache.
- `actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3`, upstream v9.0.0, calls GitHub's official REST API with the workflow token.
- `actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6`, upstream v4.2.2, creates build provenance and SPDX SBOM attestations using GitHub OIDC.
- Syft v1.51.0 for Linux amd64 is acquired from the exact official archive URL and authenticated with committed SHA-256 `2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f` before extraction or execution.
- Repository-owned standard-library code rejects oversized downloads, digest mismatches, unsafe tar paths, links, unexpected executable placement, non-executable modes, duplicate binaries, and any version other than 1.51.0.
- The authenticated Syft executable scans only the six uncompressed release binaries and emits SPDX 2.3 JSON.
- actionlint v1.7.12 validates every workflow as part of `make check` and is installed from its exact Go module version into `.tools`.

The workflow uses the automatic repository `GITHUB_TOKEN` only.
It grants `contents: write`, `checks: read`, `id-token: write`, `attestations: write`, and `artifact-metadata: write` because those are required for the release, CI gate, and attestations.
It does not use a GitHub App, personal access token, environment secret, or other external credential.
GitHub's immutable-release settings endpoint requires repository Administration read, which the automatic workflow token cannot request.
The workflow therefore makes no prepublication API claim about that setting.
Repository immutable releases are currently enabled, and the owner must confirm `Settings > Releases` still shows them enabled immediately before manually dispatching the workflow.
That manual dispatch is the approval boundary.

## Alternatives considered

### GoReleaser

GoReleaser could build archives and checksums, but it would add a broad release abstraction and a large tool trust surface for behavior that the standard library can express precisely.
Its defaults would also require careful suppression to preserve the project's exact archive and publication invariants.

### Shell-owned packaging

Platform commands such as `tar`, `zip`, and `sha256sum` are easy to invoke but have implementation-specific metadata and option behavior.
Repository-owned Go code gives one reviewed implementation for entry order, modes, timestamps, compression headers, and validation.

### GitHub CLI for workflow publication

GitHub CLI is appropriate for consumer verification, but using it for publication would add another executable whose runner-provided version is not pinned by this repository.
The pinned GitHub Script Action calls the same official API without relying on a mutable runner CLI.

### Anchore download Action

The reviewed `anchore/sbom-action/download-syft` distribution at commit `e22c389904149dbc22b58101806040fa8d37a610` delegates acquisition and execution to its bundled `anchore/syft/main/install.sh` path.
Pinning the Action commit would authenticate that script but would still make an external shell installer part of the release execution boundary.
InboxGate rejects this option and instead downloads one exact official release archive with standard-library HTTP, authenticates all bytes against a committed digest, validates the tar structure, extracts only the expected executable, and verifies its exact version.

### No SBOM or attestations

Checksums alone prove file integrity after download but not origin.
Omitting the SBOM or provenance would leave consumers unable to verify the reviewed source and described component inventory.

## Dependency and supply-chain review

### Go runtime modules

- Direct module and exact version: none.
- Complete transitive dependency impact: none in `go.mod` and no `go.sum` is introduced.
- License and compatibility: the repository remains MIT licensed and uses the Go standard library.
- Published advisories: `govulncheck` continues to scan reachable production code in `make check`.
- Maintenance and release status: the Go toolchain is exactly go1.26.6, the current stable security release reviewed on 2026-08-16.
- Security status: Go 1.26.6 fixes GO-2026-6218, GO-2026-6090, GO-2026-5972, and GO-2026-5026, which became reachable under Go 1.26.5 when repository-owned Syft acquisition added HTTPS paths.
- Checksum and provenance verification: Go module checksum verification remains part of `make check`.
- Removal or replacement plan: the release helper can be removed without changing product runtime behavior.

### actionlint v1.7.12

actionlint and its build-time dependency graph are development tools only and never enter an InboxGate binary or release archive.
The exact embedded graph reported by `go version -m` is `github.com/bmatcuk/doublestar/v4` v4.10.0, `github.com/clipperhouse/uax29/v2` v2.7.0, `github.com/fatih/color` v1.19.0, `github.com/mattn/go-colorable` v0.1.14, `github.com/mattn/go-isatty` v0.0.20, `github.com/mattn/go-runewidth` v0.0.21, `github.com/mattn/go-shellwords` v1.0.12, `github.com/robfig/cron/v3` v3.0.1, `go.yaml.in/yaml/v4` v4.0.0-rc.3, `golang.org/x/sync` v0.20.0, and `golang.org/x/sys` v0.42.0.
actionlint, doublestar, uax29, color, go-colorable, go-isatty, go-runewidth, go-shellwords, and cron use MIT-compatible licenses.
YAML v4 uses Apache-2.0, and the Go `x` modules use BSD-3-Clause.
The module checksums are verified by the Go checksum database during exact-version installation.
The upstream v1.7.12 source, release, license, module graph, and GitHub advisory status were reviewed on 2026-08-16.
The tool can be replaced by another workflow parser or removed from `make check` if GitHub provides equivalent repository validation.

### Syft v1.51.0

Syft uses the Apache-2.0 license.
The selected asset is `syft_1.51.0_linux_amd64.tar.gz` from the official immutable v1.51.0 GitHub release.
Its committed SHA-256 is `2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f`, matching the upstream `syft_1.51.0_checksums.txt` entry reviewed on 2026-08-16.
Syft is an isolated workflow executable and its Go dependencies do not enter `go.mod`, the InboxGate binary, archives, or runtime.
Its complete executable graph is the graph published in the upstream v1.51.0 source module and release materials.
The upstream release, license, checksums, maintenance activity, and GitHub advisory status were reviewed on 2026-08-16.
Synthetic HTTP, corrupt archive, unsafe path, digest mismatch, and wrong-version tests exercise acquisition without GitHub writes.
The canonical Linux amd64 `release-contract` downloads and authenticates the real archive, builds twice with isolated Go caches, executes the native binary before packaging, generates the real SBOM, and validates all artifacts.
The generated SPDX file is parsed and checked for product identity, version, required package fields, and workspace-path leakage before use.
Syft can be replaced by another pinned SPDX 2.3 generator if it stops being maintained or its output cannot satisfy those validations.

### GitHub-authored Actions

`actions/checkout`, `actions/setup-go`, `actions/github-script`, and `actions/attest` use MIT licenses.
Each is an executable JavaScript Action whose bundled transitive code is committed in its upstream distribution and fixed by the selected full commit SHA.
The complete bundled dependency impact is therefore the distribution tree at that reviewed commit rather than a dependency resolved during the InboxGate workflow.
The upstream Action metadata, lockfiles, release signatures, licenses, maintenance activity, and GitHub advisory status were reviewed on 2026-08-16.
The repository records both the immutable commit and human-readable release version so a later issue can review upgrades intentionally.
Each Action can be replaced with direct official API calls or repository-owned logic if its permissions or maintenance no longer meet this decision.

### Verification and maintenance

Every `uses:` value is a full 40-character SHA with a version comment.
The canonical check installs actionlint v1.7.12 from the exact module version and validates all workflow files.
It also invokes the real pinned Syft contract on canonical Linux amd64 CI.
Dependency maintenance remains issue-first and manual.
An actionable advisory requires a focused issue and reviewed pin update rather than an automatic dependency pull request.

## Security and privacy impact

The release workflow adds a GitHub write boundary, OIDC signing boundary, executable Action boundary, Syft tool boundary, and public artifact boundary.
Manual inputs are strictly validated before use and are passed through quoted environment variables rather than inserted into shell source.
The workflow refuses stale source, missing or failed CI, existing version objects, changed assets, and a superseded `main` head.
It verifies the published release object reports immutable state, but it cannot prove the Administration setting before publication with its automatic token.
If the setting drifts after the owner's manual check, the post-publication failure makes the release unsafe and requires separate owner-led investigation.
It verifies downloaded draft assets byte for byte immediately before the single publish operation and repeats digest verification after publication.
Immutable releases prevent later tag or asset replacement after publication.

Release assets contain only compiled binaries, `LICENSE`, `README.md`, the SPDX SBOM, and checksums.
Validation rejects workspace paths in the SBOM.
The workflow uses no Gmail, OAuth, Turso, Hermes, Vikunja, deployment, production secret, or live account data.

Failed drafts, tags, assets, and attestations are left untouched for owner investigation.
The workflow reserves the exact version tag at the expected commit before creating a draft and retains that tag on every later failure.
The workflow deliberately has no cleanup or repair path.

## Consequences

Release construction is reproducible and reviewable in this repository.
Publishing remains a deliberate owner action and fails closed when `main`, CI, metadata, assets, or repository state differs from the requested release.

SBOM JSON is not byte-reproducible because its standards-valid namespace and creation timestamp are tool-generated.
Binaries and archives remain byte-reproducible, and checksums are generated only after the SBOM is complete.

The release workflow is necessarily longer than a wrapper around a release tool.
That explicitness keeps authority, validation, and the one-way publication point visible to reviewers.

## Validation

- Run metadata tests for valid, invalid, unsafe, abbreviated, uppercase, and incomplete values.
- Cross-compile all six targets twice and compare every archive byte.
- Inspect Go build information and archive metadata.
- Execute the native Linux amd64 release binary in GitHub Actions.
- Authenticate the real Syft Linux amd64 archive before extraction or execution and test acquisition failures with a synthetic HTTP server.
- Generate and parse SPDX 2.3 JSON with the exact Syft version.
- Validate the exact eight-asset set and sorted GNU-style checksums.
- Run pinned actionlint, `make check`, `git diff --check`, and a tracked-tree cleanliness check.
- Do not dispatch the workflow until the first-release readiness gate is complete and the owner explicitly approves publication.
