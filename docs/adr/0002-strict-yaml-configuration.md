# ADR 0002: Use a pinned YAML syntax tree behind a strict schema boundary

- Status: Accepted
- Date: 2026-08-16
- Issue: #6
- Owners: @mandloideep

## Context and need

InboxGate needs a human-editable configuration file with comments and a stable versioned schema.
The Go standard library has no YAML parser.
Configuration is untrusted local input and can name secret-bearing environment variables, so permissive decoding would create ambiguity and resource-exhaustion risks.

## Decision

InboxGate uses `go.yaml.in/yaml/v3` v3.0.5 to decode YAML into a syntax tree.
Repository-owned code walks that tree before typed decoding and rejects unknown or duplicate keys, nulls, non-string keys, anchors, aliases, merges, custom tags, decoded scalar controls, noncanonical scalar forms, multiple documents, document-end markers, excessive depth, excessive nodes, and values outside the schema bounds.
The parser reads at most 65,537 bytes to enforce a 65,536-byte file limit.
It does not invoke arbitrary unmarshalling hooks, perform substitution, read environment variables named by YAML, or make network requests.
The release command imports the standard-library `time/tzdata` package so IANA timezone validation does not depend on host-installed zoneinfo data and does not change the module graph.

## Alternatives considered

### Standard library

The standard library has JSON and text primitives but no YAML parser.
Requiring JSON would remove comments and make the documented operator configuration less approachable.

### Handwritten YAML parser

A handwritten subset parser would duplicate complex Unicode, quoting, indentation, and tokenization behavior.
That would create a larger long-term correctness and security burden than constraining one established parser behind an explicit syntax-tree walk.

### Legacy module path

The legacy `gopkg.in/yaml.v3` path is superseded by the official `go.yaml.in/yaml/v3` module path.
Using the current path keeps provenance and future migration explicit.

### YAML v4 release candidate

The v4 line was still release-candidate software when this decision was accepted.
InboxGate uses the stable v3 line until v4 has a reviewed stable release and a focused migration issue.

### General configuration library

A configuration framework would add defaults, environment lookup, decoding, and merge behavior outside InboxGate's narrow contract.
Those conveniences conflict with strict presence semantics and the rule that YAML may name secrets but validation never reads them.

## Dependency and supply-chain review

- Direct module and exact version: `go.yaml.in/yaml/v3` v3.0.5.
- Complete transitive dependency impact: the module declares zero required modules, so the graph adds one direct module and no transitive modules.
- License and compatibility: upstream applies MIT and Apache-2.0 terms, both compatible with InboxGate's MIT license, and the complete notices are retained in `THIRD_PARTY_NOTICES.md` and every binary archive.
- Published advisories: planning found no applicable Go vulnerability index, OSV, or GitHub advisory entry, and `govulncheck` remains a required repository check.
- Maintenance and release status: v3.0.5 was published from official tag commit `e16c7af9361b241fa02d91582fb59ce4954d8afc` on 2026-07-26, while the API-frozen v3 line receives maintenance releases.
- Checksum and provenance verification: the Go checksum database records module checksum `h1:N6y/pJk8buWs9NY5ERU2HSMfm+IuD/OtfdAnq6kESPw=` and module-file checksum `h1:HVTZu1O7/Vkt2N+BFy8Zza+lnLsABggaTM2ZpNIGuKg=`.
- Removal or replacement plan: migrate through a focused issue to a reviewed stable YAML v4 release or to a simpler format if the human-editable YAML requirement changes.

## Security and privacy impact

This decision adds an untrusted local-file parser and one runtime dependency.
Bounded file reads, node and depth limits, regular-file enforcement, structural rejection before typed decoding, safe diagnostics, and exact semantic bounds limit that boundary.
Environment-variable names are validated as data and their values are never looked up by validation.
The parser receives no Gmail, OAuth, database, MCP, filesystem-write, or deployment authority.
The trust boundary and controls are recorded in `docs/threat-model.md`.

## Consequences

Operators can validate a complete configuration without credentials or network access.
The schema remains explicit and deterministic, but repository code must keep the typed model, example, tests, and operator documentation synchronized.
Release binaries now contain one direct module, and release archives carry its license notice.

## Validation

- Parse the complete example and a minimal version document through the real binary.
- Exercise every syntax restriction, size and complexity limit, default, semantic bound, cross-field rule, CLI exit contract, and file-path precedence rule.
- Assert the exact two-module build graph and embedded release-binary dependency metadata.
- Build deterministic release archives twice and verify the third-party notice bytes in every archive.
- Run unit, process, race, formatting, vet, module verification, vulnerability, build, and Linux release-contract checks.
