# ADR 0014: Pin the authenticated stateless MCP boundary

- Status: accepted
- Date: 2026-08-19
- Issue: #38

## Context and need

InboxGate needs one private authenticated protocol endpoint so Hermes can inspect the current binary's typed capability registry before later mail tools exist.
The existing service exposes only health routes, and the existing `capabilities` command is local operator output rather than a network protocol.
Implementing MCP framing by hand would duplicate a security-sensitive protocol, while exposing a general JSON-RPC or plugin surface would violate the bounded product model.
This is the first authenticated application endpoint and therefore creates a new network, authentication, parser, dependency, and operational trust boundary.

## Decision

Use only the root package `github.com/modelcontextprotocol/go-sdk/mcp` from exact official release `github.com/modelcontextprotocol/go-sdk v1.7.0` for MCP protocol handling.
The release is the official stable Go SDK release published on 2026-07-28 at 13:09:53 UTC.
Its signed annotated tag points to commit `bc72835f62eb94d0fb484439f886b6885b075f36`.
The SDK release documentation identifies `2026-07-28` as its latest supported MCP revision, and the official MCP 2026-07-28 release post identifies Go as one of the four Tier 1 SDKs supporting that revision on release day.
The selected module requires Go 1.25.0 and is compatible with InboxGate's pinned Go 1.26.6 toolchain.
As checked on 2026-08-19, `v1.7.0` remains the most recent non-draft, non-prerelease official Go SDK release.

InboxGate will expose only protocol revision `2026-07-28` over one exact configured Streamable HTTP path.
The endpoint will be stateless, sessionless, non-resumable, JSON-response-only, and POST-only.
The SDK handler will be configured with these exact `mcp.StreamableHTTPOptions` decisions:

```go
mcp.StreamableHTTPOptions{
	Stateless:                    true,
	JSONResponse:                 true,
	Logger:                       nil,
	EventStore:                   nil,
	MaxRequestBodyBytes:          min(serverMaxRequestBytes, 65_536),
	PropagateRequestCancellation: true,
}
```

InboxGate will explicitly construct server capabilities that advertise tools with `listChanged` false and no prompts, resources, subscriptions, logging, roots, sampling, elicitation, tasks, completion, or experimental extensions.
InboxGate will provide no SDK instructions, logger, event store, session ID generator, server-initiated request handler, or client-side feature.
The outer InboxGate registry will permit only `server/discover`, `tools/list`, and `tools/call` for the exact tool name `system_capabilities`.
Every other method or tool will fail before invoking an application dependency.
No legacy `initialize` or initialized flow will be admitted.
No older protocol revision will be negotiated even though the SDK contains compatibility support for older revisions.

Protocol revision `2026-07-28` has no initialization handshake or transport session.
Each request is self-describing and must contain exact `_meta` key `io.modelcontextprotocol/protocolVersion` with value `2026-07-28`, required bounded `io.modelcontextprotocol/clientCapabilities`, and optional bounded `io.modelcontextprotocol/clientInfo` when present.
The optional `server/discover` result will contain only the server identity, supported protocol revision, and tools capability.
Direct `tools/list` and `tools/call` requests remain valid without prior discovery.

The SDK is a protocol decoder and dispatcher inside an InboxGate-owned wrapper, not the application security policy.
InboxGate will independently own exact routing, bearer authentication, origin and browser rejection, Host validation, media negotiation, routing headers, body and JSON structure bounds, one-object enforcement, concurrency, deadline, cancellation, response buffering, fixed errors, redacted audit events, shutdown, and capability registration.
InboxGate will apply its own request-body limiter in addition to the SDK's explicit `MaxRequestBodyBytes` value.
InboxGate will buffer the complete SDK response before committing HTTP headers and will reject any response over 65,536 bytes without returning partial capability data.

The only registered tool is `system_capabilities`.
Its handler adapts `config.CapabilityRegistry` directly, accepts an empty closed object, and returns typed structured content only.
This adapter adds no Gmail, OAuth, Turso, storage, review, backfill, shell, SQL, URL-fetching, Vikunja, plugin, provider, or arbitrary JSON-RPC authority.

## Authentication and activation boundary

The existing validated `mcp.bearer_token_env` value remains an environment-variable name and never a secret value.
Only enabled `serve` resolves that name, validates one canonical 43-character unpadded RFC 4648 base64url token that decodes to 32 bytes, and constructs the handler before binding a listener.
Disabled `serve`, `doctor`, configuration commands, local capabilities, package initialization, and release construction perform no lookup.
The wrapper requires one exact `Authorization: Bearer <canonical-token>` header and accepts no query, cookie, alternate scheme, case variant, duplicate, joined, padded, or whitespace variant.
It decodes the presented token and uses `crypto/subtle.ConstantTimeCompare` over the two 32-byte values.
All missing, malformed, and incorrect credentials receive the same fixed response.
Authentication completes before the body is read or decoded and before any method-specific fact is revealed.

Repository-owned temporary byte buffers and handler-owned decoded token bytes will be cleared on close where practical.
Go strings, compiler copies, garbage-collected memory, and the process environment prevent any claim of complete zeroization.
The bearer token authenticates one approved Hermes service identity and grants no account-specific authority.
It is replayable until rotated, so an approved private route, TLS, firewall, proxy policy, secret storage, rotation, and incident response remain mandatory before deployment.

## Compatibility controls

The exact v1.7.0 SDK contains these `MCPGODEBUG` compatibility parameters:

- `allowsessionsinstateless`
- `customresnotfounderrcode`
- `disablecompleteparamsvalidation`
- `disablecontenttypecheck`
- `disablelocalhostprotection`
- `enableoriginverification`
- `hintomitempty`
- `nomethodnotfoundcodeinerror`
- `noprotocolerrorbody`
- `nowrapinvalidparams`
- `seterroroverwrite`

`allowsessionsinstateless`, `disablecontenttypecheck`, `disablelocalhostprotection`, and `enableoriginverification` can directly affect Streamable HTTP behavior if an application relies on SDK defaults.
`customresnotfounderrcode`, `disablecompleteparamsvalidation`, `hintomitempty`, `nowrapinvalidparams`, and `seterroroverwrite` can affect other server protocol or serialization behavior.
`nomethodnotfoundcodeinerror` applies to the SDK's standard-input transport, and `noprotocolerrorbody` applies to its HTTP client, neither of which InboxGate exposes.
Tests will set each parameter to its weakening value in an isolated process and will also set all parameters together.
The InboxGate wrapper must still reject sessions, old revisions, weak media, weak origin handling, broader methods, broader tools, unbounded bodies, and unowned transports.
The wrapper's owned invariants must not depend on an SDK default or on compatibility-parameter absence.

## Alternatives considered

A handwritten MCP implementation was rejected because it would duplicate JSON-RPC framing, MCP schemas, protocol evolution, and parser security work.
The official narrow SDK adapter gives InboxGate an upstream protocol implementation while keeping policy in repository-owned code.

Legacy HTTP plus SSE was rejected because the issue requires the stateless `2026-07-28` request model and must not expose a notification stream, resumability, or deprecated transport.

Stateful Streamable HTTP was rejected because session identifiers, lifecycle state, resumability, GET streams, and DELETE behavior add unnecessary state and authorization ambiguity.

Older MCP revisions were rejected because initialization negotiation, transport sessions, and older routing semantics broaden the test matrix and downgrade surface without serving this first tool.

A generic JSON-RPC framework was rejected because it would require InboxGate to implement the MCP protocol above it and could expose custom methods outside the typed registry.

A broader provider, plugin, or agent framework was rejected because InboxGate is a deterministic Gmail data service with a closed capability surface, not a general execution host.

## Exact dependency graph

The upstream `v1.7.0` module declaration contains these requirements:

```text
github.com/golang-jwt/jwt/v5 v5.3.1
github.com/google/go-cmp v0.7.0
github.com/google/jsonschema-go v0.4.3
github.com/segmentio/encoding v0.5.4
github.com/yosida95/uritemplate/v3 v3.0.2
golang.org/x/oauth2 v0.35.0
golang.org/x/time v0.15.0
golang.org/x/tools v0.42.0
github.com/segmentio/asm v1.1.3 // indirect
golang.org/x/sync v0.20.0 // indirect
golang.org/x/sys v0.41.0 // indirect
```

InboxGate already pins `golang.org/x/oauth2 v0.36.0`, so minimum version selection retains that higher version.
An isolated module file containing the current InboxGate direct requirements plus the proposed SDK pin produced this exact `go list -m all` output:

```text
inboxgate.local/mcp-adr-evidence
cloud.google.com/go/compute/metadata v0.3.0
github.com/golang-jwt/jwt/v5 v5.3.1
github.com/google/go-cmp v0.7.0
github.com/google/jsonschema-go v0.4.3
github.com/modelcontextprotocol/go-sdk v1.7.0
github.com/segmentio/asm v1.1.3
github.com/segmentio/encoding v0.5.4
github.com/yosida95/uritemplate/v3 v3.0.2
go.yaml.in/yaml/v3 v3.0.5
golang.org/x/oauth2 v0.36.0
golang.org/x/sync v0.20.0
golang.org/x/sys v0.41.0
golang.org/x/time v0.15.0
golang.org/x/tools v0.42.0
turso.tech/database/tursogo-serverless v0.0.0-20260817122138-24adc316cdc4
```

After production imports, `go mod tidy` records the SDK packages that contribute linked code as explicit indirect root requirements under Go 1.26 module pruning.
This adds root edges for already accepted modules and exposes their already accepted minimum Go and minimum `golang.org/x/sys` edges without changing the selected module or version set.
The production module now produces this exact `go mod graph` output:

```text
github.com/mandloideep/inboxgate github.com/google/jsonschema-go@v0.4.3
github.com/mandloideep/inboxgate github.com/modelcontextprotocol/go-sdk@v1.7.0
github.com/mandloideep/inboxgate github.com/segmentio/asm@v1.1.3
github.com/mandloideep/inboxgate github.com/segmentio/encoding@v0.5.4
github.com/mandloideep/inboxgate github.com/yosida95/uritemplate/v3@v3.0.2
github.com/mandloideep/inboxgate go@1.26.0
github.com/mandloideep/inboxgate go.yaml.in/yaml/v3@v3.0.5
github.com/mandloideep/inboxgate golang.org/x/oauth2@v0.36.0
github.com/mandloideep/inboxgate golang.org/x/sync@v0.20.0
github.com/mandloideep/inboxgate golang.org/x/sys@v0.41.0
github.com/mandloideep/inboxgate golang.org/x/time@v0.15.0
github.com/mandloideep/inboxgate toolchain@go1.26.6
github.com/mandloideep/inboxgate turso.tech/database/tursogo-serverless@v0.0.0-20260817122138-24adc316cdc4
github.com/google/jsonschema-go@v0.4.3 github.com/google/go-cmp@v0.7.0
github.com/google/jsonschema-go@v0.4.3 go@1.23.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/golang-jwt/jwt/v5@v5.3.1
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/google/go-cmp@v0.7.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/google/jsonschema-go@v0.4.3
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/segmentio/encoding@v0.5.4
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/yosida95/uritemplate/v3@v3.0.2
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/oauth2@v0.35.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/time@v0.15.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/tools@v0.42.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/segmentio/asm@v1.1.3
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/sync@v0.20.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/sys@v0.41.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 go@1.25.0
github.com/segmentio/asm@v1.1.3 golang.org/x/sys@v0.0.0-20211110154304-99a53858aa08
github.com/segmentio/encoding@v0.5.4 github.com/segmentio/asm@v1.1.3
github.com/segmentio/encoding@v0.5.4 golang.org/x/sys@v0.0.0-20211110154304-99a53858aa08
github.com/segmentio/encoding@v0.5.4 go@1.23
go@1.26.0 toolchain@go1.26.0
golang.org/x/oauth2@v0.36.0 cloud.google.com/go/compute/metadata@v0.3.0
golang.org/x/oauth2@v0.36.0 go@1.25.0
golang.org/x/sync@v0.20.0 go@1.25.0
golang.org/x/sys@v0.41.0 go@1.24.0
golang.org/x/time@v0.15.0 go@1.25.0
turso.tech/database/tursogo-serverless@v0.0.0-20260817122138-24adc316cdc4 go@1.24.0
```

The production dependency commit must stop if `go mod tidy`, `go list -m all`, or `go mod graph` resolves a different module or version without an amended and accepted ADR.

## Checksums and licenses

The Go checksum database evidence for every module introduced by the SDK declaration and the already higher OAuth selection is:

| Module | Content sum | `go.mod` sum |
| --- | --- | --- |
| `github.com/golang-jwt/jwt/v5 v5.3.1` | `h1:kYf81DTWFe7t+1VvL7eS+jKFVWaUnK9cB1qbwn63YCY=` | `h1:fxCRLWMO43lRc8nhHWY6LGqRcf+1gQWArsqaEUEa5bE=` |
| `github.com/google/go-cmp v0.7.0` | `h1:wk8382ETsv4JYUZwIsn6YpYiWiBsYLSJiTsyBybVuN8=` | `h1:pXiqmnSA92OHEEa9HXL2W4E7lf9JzCmGVUdgjX3N/iU=` |
| `github.com/google/jsonschema-go v0.4.3` | `h1:/DBOLZTfDow7pe2GmaJNhltueGTtDKICi8V8p+DQPd0=` | `h1:r5quNTdLOYEz95Ru18zA0ydNbBuYoo9tgaYcxEYhJVE=` |
| `github.com/modelcontextprotocol/go-sdk v1.7.0` | `h1:yqjY2dsbKAC0LSuWZVBMrHgiG8ukXv6NRo0JiALay44=` | `h1:dL7u98E/zjJTGzEq+j30jQ8K2k1mb6LeAH4inEcSGts=` |
| `github.com/segmentio/asm v1.1.3` | `h1:WM03sfUOENvvKexOLp+pCqgb/WDjsi7EK8gIsICtzhc=` | `h1:Ld3L4ZXGNcSLRg4JBsZ3//1+f/TjYl0Mzen/DQy1EJg=` |
| `github.com/segmentio/encoding v0.5.4` | `h1:OW1VRern8Nw6ITAtwSZ7Idrl3MXCFwXHPgqESYfvNt0=` | `h1:HS1ZKa3kSN32ZHVZ7ZLPLXWvOVIiZtyJnO1gPH1sKt0=` |
| `github.com/yosida95/uritemplate/v3 v3.0.2` | `h1:Ed3Oyj9yrmi9087+NczuL5BwkIc4wvTb5zIM+UJPGz4=` | `h1:ILOh0sOhIJR3+L/8afwt/kE++YT040gmv5BQTMR2HP4=` |
| `golang.org/x/oauth2 v0.36.0` | `h1:peZ/1z27fi9hUOFCAZaHyrpWG5lwe0RJEEEeH0ThlIs=` | `h1:YDBUJMTkDnJS+A4BP4eZBjCqtokkg1hODuPjwiGPO7Q=` |
| `golang.org/x/sync v0.20.0` | `h1:e0PTpb7pjO8GAtTs2dQ6jYa5BWYlMuX047Dco/pItO4=` | `h1:9xrNwdLfx4jkKbNva9FpL6vEN7evnE43NNNJQ2LF3+0=` |
| `golang.org/x/sys v0.41.0` | `h1:Ivj+2Cp/ylzLiEU89QhWblYnOE9zerudt9Ftecq2C6k=` | `h1:OgkHotnGiDImocRcuBABYBEXf8A9a87e/uXjp9XT3ks=` |
| `golang.org/x/time v0.15.0` | `h1:bbrp8t3bGUeFOx08pvsMYRTCVSMk89u4tKbNOZbp88U=` | `h1:Y4YMaQmXwGQZoFaVFk4YpCt4FLQMYKZe9oeV/f4MSno=` |
| `golang.org/x/tools v0.42.0` | `h1:uNgphsn75Tdz5Ji2q36v/nsFSfR/9BRFvqhGBaJGd5k=` | `h1:Ma6lCIwGZvHK6XtgbswSoWroEkhugApmsXyrUmBhfr0=` |

The exact license-file evidence reviewed from the selected module archives is:

| Module | License evidence | License-file SHA-256 |
| --- | --- | --- |
| `github.com/golang-jwt/jwt/v5 v5.3.1` | MIT | `fe26ca41577b9b2b4448050a24b25e5753af66b5d5945d5d36094e7790bfcb2f` |
| `github.com/google/go-cmp v0.7.0` | BSD 3-Clause | `17b5d209ba8f9684257ecfcff87df6ceda6194143a8fbd074f29727cff6f0c40` |
| `github.com/google/jsonschema-go v0.4.3` | MIT | `2d56c53449691d85d9aea245eb8dac12713e9075d70d5557b82ae1e94805b357` |
| `github.com/modelcontextprotocol/go-sdk v1.7.0` | Transition notice covering Apache-2.0, retained MIT contributions, and CC-BY-4.0 documentation | `af679003d933f045393a6a029f43da113f9ae364eac651d9ae268392985580f5` |
| `github.com/segmentio/asm v1.1.3` | MIT | `e2a78de21d6d8ded2dff0f3189cd32e011630d785da127ebfbc8949012c0947b` |
| `github.com/segmentio/encoding v0.5.4` | MIT | `d6d71a1f7dc6539e371120cc7af6e3257e55ca79634d473211f217b8965b0f16` |
| `github.com/yosida95/uritemplate/v3 v3.0.2` | BSD 3-Clause | `0761aadfb1921103752869ee942d4a71bdd54494697684d4b13dc17ad9781191` |
| `golang.org/x/oauth2 v0.36.0` | BSD 3-Clause | `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad` |
| `golang.org/x/sync v0.20.0` | BSD 3-Clause | `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad` |
| `golang.org/x/sys v0.41.0` | BSD 3-Clause | `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad` |
| `golang.org/x/time v0.15.0` | BSD 3-Clause | `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad` |
| `golang.org/x/tools v0.42.0` | BSD 3-Clause | `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad` |

The SDK's license file explicitly states that new code and specification contributions use Apache-2.0, contributions not yet relicensed remain under MIT, and non-specification documentation uses CC-BY-4.0.
All selected licenses are compatible with distribution under InboxGate's MIT license when their notices and applicable attribution terms are retained.
The dependency implementation must update `THIRD_PARTY_NOTICES.md` for every newly distributed module and must preserve the exact SDK transition notice rather than describing the SDK as licensed only under one license.
Existing notices for `go.yaml.in/yaml/v3`, `golang.org/x/oauth2`, `cloud.google.com/go/compute/metadata`, and `turso.tech/database/tursogo-serverless` remain required and unchanged except for any additive organization needed to include the reviewed MCP graph.

## Advisory review

The official GitHub Advisory Database records four published high-severity advisories for earlier SDK releases.

| Advisory | Affected versions and fix | Disposition for v1.7.0 |
| --- | --- | --- |
| `GHSA-xw59-hvm2-8pj6` | SDK versions before 1.4.0 lacked default localhost DNS-rebinding protection, fixed in 1.4.0. | The selected version contains the fix, and InboxGate independently validates Host and rejects browser and origin traffic. |
| `GHSA-89xv-2j6f-qhc8` | SDK versions through 1.4.0 accepted unsafe cross-site POST conditions, fixed in 1.4.1. | The selected version contains the fix, and InboxGate independently enforces exact media, rejects every Origin and CORS request header, and emits no CORS allow header. |
| `GHSA-q382-vc8q-7jhj` | SDK versions through 1.4.0 were vulnerable to NUL-suffixed JSON key matching, fixed in 1.4.1 using patched `github.com/segmentio/encoding v0.5.4`. | The selected graph contains `segmentio/encoding v0.5.4`, and InboxGate independently rejects NUL aliases, duplicate security fields, non-exact case, batches, trailing values, and routing mismatches. |
| `GHSA-wvj2-96wp-fq3f` | SDK versions before 1.3.1 accepted case-folded JSON-RPC field names, fixed in 1.3.1. | The selected version contains the fix, and InboxGate independently tests exact JSON field spelling and Unicode folding cases. |

The accepted `v1.7.0` pin is newer than every published fixed version above.
This disposition does not delegate InboxGate's trust boundary to the dependency.
Any new reachable unresolved advisory or graph drift blocks merge and requires an amended decision or different exact pin.

## Security and privacy impact

This decision activates code for one authenticated private endpoint but does not authorize deployment, a live token, Hermes connection, public exposure, live Gmail, or live Turso.
The SDK does not replace bearer authentication, authorization, TLS, private routing, firewall policy, proxy validation, origin rejection, exact Host policy, exact media validation, route policy, body bounds, structural bounds, concurrency, deadlines, response bounds, fixed errors, audit redaction, rotation, or incident response.
The SDK logger remains nil because request data, client metadata, tool arguments, and diagnostics are sensitive.
Only fixed allowlisted audit fields may leave the wrapper, and no Authorization data, body, headers, Host, URL, query, path, IP, user agent, client identity, client capabilities, environment name, response, token state, or SDK error may be logged.

The response exposes operational metadata, capability names, and validated secret environment-variable names.
It therefore remains authenticated and must not be copied into a public issue or log without review.
Email content remains untrusted data and cannot become protocol instructions or authority through this endpoint.
Gmail remains read-only and unreachable in this slice.

The exact SDK and transitive graph add a supply-chain and parser trust dependency.
Immutable version and checksum pins, exact graph tests, license notices, advisory review, `go mod verify`, `go mod tidy -diff`, `make vuln`, SBOM inclusion, and all supported release builds are mandatory controls.
Compatibility flags are ambient process input, so isolated negative tests must prove that none broadens the InboxGate wrapper.

## Capability-surface impact

The application and domain layers reuse the existing typed `config.CapabilityRegistry` through one read-only adapter.
The HTTP runtime adds one exact authenticated POST route only when `mcp.enabled` is true.
The MCP surface adds `server/discover`, `tools/list`, and `tools/call` only for `system_capabilities` under exact revision `2026-07-28`.
Configuration adds no key and stores only the existing secret environment-variable name.
Storage, migrations, Gmail, OAuth, Turso, review, backfill, metrics, shell, SQL, URL fetching, and Vikunja gain no reachable behavior.
Health response bodies remain unchanged, while enabled readiness waits for token resolution and handler construction.
Audit output adds only fixed redacted runtime events and no durable table.

## Removal and rollback

Immediate rollback sets `mcp.enabled: false` and redeploys, which removes the route and avoids token resolution without changing stored data.
Operational rollback may instead redeploy the previously validated binary.
No stored-data rollback or migration is required because this decision creates no durable MCP state.
A later replacement must implement the same narrow adapter, pass the full wire and capability contract, and be accepted before the official SDK is removed.
Removing the SDK, notices, tests, or adapter files requires a separate approved deletion-aware issue and owner action under `DELETION_REQUESTS.md`.
This issue deletes, renames, truncates, and replaces no pre-existing file.

## Acceptance boundary and validation

The comprehensive tests-only red commit `acbe7e9a6c2613854d6073ef51292e96b1bb15b2` predates this ADR, dependency changes, SDK imports, and production behavior.
This ADR must receive explicit orchestrator acceptance before `go.mod`, `go.sum`, `THIRD_PARTY_NOTICES.md`, an SDK import, or production behavior changes.
After acceptance, the implementation must pin only the graph above and stop if actual module resolution differs.

Validation must include focused repeated handler tests, isolated compatibility-flag tests, real-process literal-loopback tests, bounded fuzz and property tests, race tests for authentication close, concurrency, cancellation, and shutdown, and the full repository suite.
It must also include `go mod tidy -diff`, `go mod verify`, exact `go list -m all`, exact `go mod graph`, checksum and notice review, `make vuln`, `make check`, SBOM inclusion, and all six CGO-disabled release-target builds.
The final review must inventory runtime imports and methods, dependency and license impact, secret access, network endpoints, capabilities, Gmail and storage authority, workflow and release changes, deletions, em dash characters, and coauthors.

## Evidence sources

- Official SDK release: <https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.7.0>
- Official SDK source and compatibility table: <https://github.com/modelcontextprotocol/go-sdk/tree/v1.7.0>
- Official MCP 2026-07-28 release and Tier 1 SDK list: <https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/blog/content/posts/2026-07-28-spec-ga/index.md>
- Official SDK tier definitions: <https://modelcontextprotocol.io/community/sdk-tiers>
- SDK advisory `GHSA-xw59-hvm2-8pj6`: <https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-xw59-hvm2-8pj6>
- SDK advisory `GHSA-89xv-2j6f-qhc8`: <https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-89xv-2j6f-qhc8>
- SDK advisory `GHSA-q382-vc8q-7jhj`: <https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-q382-vc8q-7jhj>
- SDK advisory `GHSA-wvj2-96wp-fq3f`: <https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-wvj2-96wp-fq3f>
- Go checksum database: <https://sum.golang.org/>
