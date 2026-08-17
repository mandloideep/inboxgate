# Security policy

## Supported versions

InboxGate has not published a supported release yet.
Security fixes currently target the default branch.
This table will be updated when `v0.1.0` is published.

| Version | Supported |
| --- | --- |
| Unreleased `main` | Yes |
| Published releases | None yet |

## Report a vulnerability

Do not open a public issue for a suspected vulnerability.
Use [GitHub private vulnerability reporting](https://github.com/mandloideep/inboxgate/security/advisories/new).

Include the affected revision, impact, reproduction steps, and any suggested mitigation.
Remove credentials, email content, account identifiers, and other personal data from the report.
The maintainer will acknowledge reports and coordinate remediation and disclosure on a best-effort basis.

## Security boundaries

InboxGate must request read-only Gmail permissions and must not expose arbitrary Gmail calls, raw SQL, shell execution, or URL fetching.
Provider credentials must never appear in configuration files, logs, fixtures, issues, or pull requests.
See [docs/threat-model.md](docs/threat-model.md) for the current security assumptions and required review triggers.
