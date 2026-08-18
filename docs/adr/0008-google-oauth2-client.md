# ADR 0008: Pin the Google OAuth 2.0 client boundary

Status: accepted

Date: 2026-08-17

Issue: #26

## Context and need

InboxGate needs a standards-conformant confidential Web application authorization-code exchange with PKCE for one bounded Gmail enrollment command.
The standard library supplies HTTP, URL, randomness, and cryptography primitives but does not supply interoperable OAuth authorization construction and token exchange behavior.
Provider discovery, automatic token refresh, application-default credentials, ID-token processing, and a generic provider abstraction are outside this decision.

## Decision

Use `golang.org/x/oauth2` at exact version `v0.36.0` and only its root package.
Use `Config.AuthCodeURL` with explicit offline access, consent and account-selection prompt, state, and S256 PKCE parameters.
Use `Config.Exchange` once with `AuthStyleInParams`, the exact redirect URI, and an InboxGate-owned HTTP client supplied through the request context.
Do not use `oauth2.NewClient`, `TokenSource`, automatic refresh, provider endpoint packages, discovery, or application-default credentials.

Production authorization, token, UserInfo, and Gmail profile endpoints remain fixed in repository code.
Only same-package tests may substitute credential-free literal-loopback endpoints.
InboxGate owns redirect rejection, a fresh proxy-disabled transport with explicit dial and verified TLS policy, response-header timeouts, one 15-second request deadline, pre-decode response limiting, duplicate-aware JSON and form validation before dependency decoding, and fixed diagnostic mapping.

## Alternatives considered

A handwritten standard-library exchange would reduce the module graph but would duplicate security-sensitive OAuth request construction and token response compatibility behavior.
Using Google's broader API client would add discovery, credential acquisition, transport, and service surface that this command does not need.
Doing nothing would require an operator to handle authorization data manually and bypass the encrypted staged-persistence boundary.

## Dependency and supply-chain review

The direct module is `golang.org/x/oauth2 v0.36.0`, tag commit `4d954e69a88d9e1ccb8439f8d5b6cbef230c4ef9`.
Its only required module is `cloud.google.com/go/compute/metadata v0.3.0`.
InboxGate does not import or call the metadata module, but it remains in the complete build graph.
The OAuth module uses the BSD 3-Clause license and the metadata module uses Apache License 2.0, both compatible with InboxGate's MIT distribution when their notices are retained.
The selected OAuth release requires Go 1.25 and is compatible with the repository's pinned Go 1.26.6 toolchain.
The module is maintained by the Go project and uses the official Go module proxy checksum and VCS provenance recorded in `go.sum`.
The acceptance requires `govulncheck ./...` to report no reachable vulnerability for the selected graph on 2026-08-17.
Any reachable unresolved advisory blocks this decision and requires a new exact version review.

The dependency budget is one direct and one indirect module.
Removal replaces authorization construction and exchange with a separately reviewed standard-library implementation, deletes both graph entries if unused, updates notices, and reruns the complete OAuth wire contract.

## Security and privacy impact

This dependency processes an authorization code, PKCE verifier, client credentials, access token, refresh token, redirect URI, and granted scope text in memory.
InboxGate maps every dependency failure to a fixed bounded category and never returns the dependency error or provider body.
The owned transport rejects redirects so authorization data and bearer tokens cannot be forwarded to another request target.
The response wrapper rejects more than 16,384 bytes and rejects malformed, trailing, unexpected-encoding, duplicate-field, or noncanonical sensitive-field token responses before OAuth decoding can continue.
Repository-owned mutable code, token, verifier, client-secret, keyring, and plaintext buffers are cleared where practical without claiming complete Go process-memory zeroization.

## Consequences

InboxGate gains one narrow reviewed OAuth exchange boundary and one indirect module that is unreachable through the selected root-package calls.
The long-running service remains health-only, Gmail synchronization remains disabled, and live authorization remains prohibited until separate owner approval and runtime storage activation.

## Validation

Tests assert the exact authorization query, request-body client authentication, token form, PKCE values, redirect rejection, duplicate sensitive-field rejection, body limits, scope validation, cancellation, fixed diagnostics, no retry, and absence of automatic refresh.
The dependency graph, checksums, licenses, vulnerability scan, focused repeated tests, race tests, and six supported target builds must pass before merge.
