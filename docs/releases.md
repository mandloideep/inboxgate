# Releases

InboxGate releases are deliberate owner operations from an exact reviewed `main` commit.
No release is created automatically when code merges.

## Version policy

InboxGate follows Semantic Versioning and remains pre-1.0 while its initial interfaces are being established.
Use a minor version for a meaningful compatible feature slice.
Use a patch version for a compatible fix or security update.
The release workflow accepts only canonical `v0.<minor>.<patch>` versions with a nonzero minor and no prerelease or build suffix.

GitHub-generated release notes describe each release.
Do not create or manually maintain `CHANGELOG.md`.
The workflow never creates floating `v0` or `v0.<minor>` tags.

## First-publication gate

Do not publish `v0.1.0` until all of the following behaviors are merged and freshly verified on `main`:

- Strict configuration validation.
- Redacted effective configuration.
- Typed capabilities.
- `serve` with liveness and readiness.
- Graceful shutdown.
- `doctor` diagnostics.

The initial remote draft, attestation, and immutable-publication exercise is an explicit owner operation after this gate.

## Owner release procedure

1. Confirm the target is the current `main` commit and its latest completed `ci-required` check succeeded.
2. Immediately before selecting `Run workflow`, open repository `Settings > Releases` and confirm immutable releases remain enabled.
3. Open the `Release` workflow and select `Run workflow` from `main`.
4. Enter an unused exact version such as `v0.1.0` and the full lowercase 40-character `main` SHA.
5. Inspect the completed workflow, generated release, exact eight assets, attestations, and tag target.
6. Record the release URL, tag, commit, and verification evidence in the approved release issue.

The workflow reruns all repository checks and builds every supported platform twice.
It creates a draft only after local verification, downloads every uploaded asset for digest verification, and performs one publication operation.
Published releases must report immutable state.
Repository immutable releases are currently enabled, but the automatic workflow token cannot read that Administration setting.
The manual dispatch is the owner's approval that the setting was checked immediately before the run.

The workflow uses only its automatic repository token.
It does not use a GitHub App, personal access token, environment secret, production credential, or provider credential.

## Failure handling

The workflow reserves the exact version tag at the requested commit before creating the draft.
It never deletes or repairs a failed draft, workflow-created tag, asset, or attestation.
If it fails before publication, stop and inspect the retained GitHub state.
Do not rerun with the same version because reruns are rejected and the reserved tag is retained.
The owner must resolve retained state through a separate approved issue before filing a new release attempt.
If `main` changes during a run, the workflow refuses publication and leaves any draft intact for investigation.
If the immutable-release setting drifted despite the manual check, post-publication verification fails.
The owner must treat that release as unsafe, stop distribution, preserve the evidence, and resolve it through a separate approved issue.

Cancellation and timeout are failures, not authorization to publish manually.
Do not bypass the workflow's checks with a local release.

## Consumer verification

Replace `v0.1.0` and the archive name below with the release being installed.
Run verification before executing the binary.

```sh
gh release verify v0.1.0 --repo mandloideep/inboxgate
gh release download v0.1.0 --repo mandloideep/inboxgate
gh release verify-asset v0.1.0 inboxgate_0.1.0_linux_amd64.tar.gz --repo mandloideep/inboxgate
gh attestation verify inboxgate_0.1.0_linux_amd64.tar.gz --repo mandloideep/inboxgate --signer-workflow mandloideep/inboxgate/.github/workflows/release.yml
sha256sum --check SHA256SUMS
```

On macOS, use `shasum -a 256 -c SHA256SUMS` when GNU `sha256sum` is unavailable.
The checksum file covers all six platform archives and the SPDX SBOM.
The build-provenance attestation covers all eight published assets.
A separate SBOM attestation associates the SPDX document with all six archives.

Each archive contains one versioned top-level directory with the platform binary, `LICENSE`, `README.md`, and `THIRD_PARTY_NOTICES.md`.
Linux and macOS archives use `.tar.gz`, while Windows archives use `.zip`.
