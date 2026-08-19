# Owner setup and blocker runbook

This guide explains what currently blocks InboxGate, what may require owner action later, and how to prepare provider and runtime access without disclosing credentials to an agent.
It is an operational checklist, not authorization to deploy, create production credentials, grant OAuth consent, access live accounts, or write to a production database.
Complete a provider step only after the corresponding implementation issue is accepted and explicitly requests that step.

## Current blocker

No owner credential or provider setup is required to implement, review, merge, or synthetically validate Gmail OAuth enrollment, current discovery, deterministic persisted gating, or bounded candidate-content extraction.
[ADR 0004](adr/0004-turso-serverless-adapter.md) accepts the current official `turso.tech/database/tursogo-serverless` remote driver behind a narrow inert adapter.
[ADR 0005](adr/0005-append-only-migration-protocol.md) adds an embedded migration ledger and runner restricted to credential-free literal-loopback tests.
[ADR 0006](adr/0006-minimum-account-cursor-persistence.md) adds minimum Gmail identity and synchronization-cursor persistence under the same credential-free literal-loopback restriction.
[ADR 0007](adr/0007-versioned-provider-credential-encryption.md) adds standard-library versioned authenticated encryption and ciphertext-only provider-credential persistence under the same restriction.
[ADR 0009](adr/0009-account-lifecycle-and-revocation.md) adds strict lifecycle persistence, bounded operator commands, and synthetic provider revocation.
[ADR 0010](adr/0010-atomic-current-discovery-staging.md) adds bounded atomic current-discovery staging and canonical metadata persistence under the same restriction.
[ADR 0011](adr/0011-bounded-gmail-current-discovery.md) adds one bounded internal Gmail current-discovery invocation against synthetic OAuth and Gmail providers and fake or credential-free literal-loopback storage.
[ADR 0012](adr/0012-deterministic-persisted-gate.md) adds one pure deterministic classifier, a strict append-only gate-decision table, typed fake and Turso persistence, and an inert evaluator under the same credential-free restriction.
[ADR 0013](adr/0013-bounded-candidate-content.md) adds one bounded read-only Gmail content projection, fail-closed MIME, charset, and HTML processing, strict append-only candidate-content persistence, and an inert extractor under the same credential-free restriction.
The adapter is connected only to one-shot account enrollment and lifecycle commands after a credential-free literal-loopback endpoint check.
The current-discovery use case, gate evaluator, and candidate-content extractor remain inert and have no command, scheduler, service, health, capability, HTTP, or MCP caller.
It remains disconnected from service startup, health, configuration inspection, capabilities, doctor, executable synchronization, MCP, remote database endpoints, and production credentials.

The owner accepts five unresolved driver risks for the exact selected version.

- A server-provided `base_url` can change authority before a later request carries the bearer token.
- Valid remote error text can be reflected by the driver.
- The driver's transaction helpers and stream close use background requests, a failed pipeline sequence has uncertain terminal state, a nil rollback response cannot prove cleanup completion, and the exact driver does not validate sequence payload type or require a true autocommit observation.
- Synthetic migrations therefore require locked exact-pair ledger-prefix validation with null rejection during both application and terminal repair, a regression-resistant same-session `user_version` probe, separate durable ledger and marker verification, and forced pool discard when session state is unproven.
- The driver owns a private HTTP client without an injectable redirect, transport, or timeout policy.
- Successful pipeline bodies, cursor lines, rows, and individual values lack repository-owned total limits.

These items remain open in the [known-risk register](known-risks.md) and are not fixed by the adapter.
The encryption and credential-persistence slice uses synthetic keys and ciphertext only and requires no owner action.
The atomic current-discovery slice uses synthetic untrusted metadata and a credential-free loopback protocol model and requires no owner action.
The bounded Gmail discovery slice uses synthetic refresh material, synthetic account and message data, fixed loopback provider transports, and fake or credential-free literal-loopback storage and requires no owner action.
It performs one synthetic access-token refresh, at most ten bounded history pages, body-excluding projected message metadata reads, and one atomic storage commit.
The deterministic gate slice uses synthetic canonical messages, compiled policy values, fake storage, and credential-free literal-loopback storage and requires no owner action.
The candidate-content slice uses synthetic message bodies and HTML, fake provider transports, fake storage, and credential-free literal-loopback exact-driver storage and requires no owner action.
It does not access live Gmail, fetch attachments, activate remote Turso, expose content through MCP, or enforce `retention.excerpt_days` deletion.
No owner should create, inject, reveal, or test a Google, Gmail, Turso, encryption, private-endpoint, or production value for these slices.
The model does not execute a Turso Database engine and does not prove the 514-parameter statement, strict tables, trigger rollback, writer serialization, or concurrent finalization.
A supplementary credential-free local SQLite execution proves commitment mismatch rollback with an unchanged cursor, no canonical insert, and retained sealed recovery state, but it does not replace Turso Database engine evidence.
The implemented one-shot enrollment flow remains restricted to fake OAuth, OpenID Connect, Gmail, and credential-free loopback storage until explicit owner approval and database runtime activation.
Production setup, credential creation, live connectivity, and database writes remain blocked until a separate approved issue requests them and the owner explicitly authorizes them.

## What you can decide now

The owner can provide the following non-secret operating decisions before production-readiness work is planned.

1. State the required deployment and network constraints, such as outbound policy, private routing, TLS termination ownership, and whether an additional service can be operated.
2. State the required region, availability, recovery window, and recovery-drill expectations without naming an account or database.
3. If a database already exists, state only whether it is a new Turso Database or a legacy libSQL database.
4. Decide whether a maintained fork or separately operated protocol proxy may be evaluated later to close accepted risks.
5. State which operator role may approve the first production migration and recovery drill.

Provide only decisions and non-identifying status.
Do not provide an organization name, database name, endpoint, account identifier, token, connection string, or other credential.

## Readiness summary

Use these status meanings throughout this runbook.

- `Blocking now` means work cannot safely proceed until the stated architecture problem is resolved.
- `Resolved for the inert adapter` means the code-level architecture decision is accepted but no production setup or activation follows automatically.
- `Future owner action` means the owner will need to act after an implementation issue defines and requests the exact prerequisite.
- `Not yet actionable` means no owner setup or credential creation should occur with the current binary.
- `Optional release operation` means an approved owner may deliberately publish the current reviewed software, independently of deployment or provider readiness.

| Area | Status | What the owner should do now | What unblocks it |
| --- | --- | --- | --- |
| Turso architecture | `Resolved for synthetic migrations and inert typed persistence` | Review ADR 0004 through ADR 0013 and the known-risk register | A later superseding decision only if the driver or architecture changes |
| Turso Cloud setup | `Not yet actionable` | Do not create or provide InboxGate credentials | An approved production-readiness issue with explicit owner authorization |
| Google OAuth and Gmail | `Future owner action` | Decide which Google organization and test accounts will own consent, without sharing identifiers | Explicit owner approval and approved live storage activation |
| Encryption key | `Future owner action` | Do not generate or provide a key yet | Runtime secret resolution, an approved credential rotation workflow, and explicit owner approval |
| MCP and Hermes | `Future owner action` | Reserve a private connectivity design, without creating a token | Authenticated MCP transport and an approved integration issue |
| Private deployment | `Future owner action` | Identify the intended private host, firewall owner, TLS boundary, and recovery owner | Hardened deployment guidance and explicit deployment approval |
| GitHub release | `Optional release operation` | Use the repository UI only for an approved release | Current `main`, passing `ci-required`, immutable releases, and approved version inputs |

## Foreseeable blockers

These conditions are not all active today.
They are listed so the owner can recognize the safe next action when the relevant implementation phase begins.

| Condition | When it matters | Safe owner action |
| --- | --- | --- |
| Accepted Turso driver risks | Before any runtime activation, credential use, migration, or new query path | Review `TURSO-001` through `TURSO-005`, keep the use within the explicit acceptance, and require a new decision if the surface broadens |
| Current-discovery engine semantics unproven | Before remote migration `0005` or live email metadata storage | Require pinned credential-free engine evidence or approve a redacted owner-run check for the exact 514-parameter statement, ordered `group_concat` witness reconstruction, strict tables, trigger rollback, writer serialization, and competing finalization without sharing database or message data |
| Gate-decision engine semantics unproven | Before remote migration `0006` or live gate-decision storage | Require pinned credential-free engine evidence or approve a redacted owner-run check for the strict table, restrictive foreign key, fixed compare-and-swap statement, competing writers, and separate-connection visibility without sharing database or message data |
| Candidate-content engine semantics unproven | Before remote migration `0007` or live excerpt storage | Require pinned credential-free engine evidence or approve a redacted owner-run check for the strict table, restrictive foreign key, lifecycle and gate joins, exact compare-and-swap statement, competing writers, and separate-connection visibility without sharing database, account, or message data |
| Excerpt retention is policy only | Before executable extraction or release readiness claims retention enforcement | Approve a separate bounded deletion and recovery issue, then require synthetic expiry, interruption, restart, and audit evidence before activation |
| Stale Gmail history cursor | Before executable synchronization or release | Require a later approved slice to persist bounded stale status and perform restart-safe full reconciliation without silently resetting the cursor or starting an unlimited backfill |
| Google testing-mode refresh-token expiration | During OAuth enrollment testing for an external app that remains in testing mode | Review Google's current testing-mode policy and plan reauthorization or approved publication without sharing tokens or user identities |
| Google Workspace administrator restrictions | Before authorizing a managed Workspace account | Ask the Workspace administrator to review the exact read-only scope and app policy through Google controls |
| Google OAuth verification requirement | Before use outside an exempt, permitted testing, or eligible internal audience | Recheck audience applicability and exemptions, then complete Google's owner-managed verification process when required |
| Restricted-scope security assessment | When Google's current rules require an assessment because the service stores or transmits Restricted scope data on a server | Use Google's approved assessment process and do not enroll production accounts until the requirement is satisfied or an applicable exemption is confirmed |
| Public app identity and domain requirements | When current Google verification rules require a public homepage, privacy policy, or verified owned domain | Publish accurate owner-controlled pages on the verified domain and authorize the domain through Google controls without sharing private account details |
| Separate testing and production projects | When Google's current policies or the approved rollout require environment isolation | Keep testing credentials and users in an owner-controlled testing project and production consent and credentials in a separately approved production project |
| Exact OAuth callback URI mismatch or rejection | Before choosing callback routing, creating the OAuth client, or enrolling an account | Validate the proposed URI against Google's current web-server rules, then compare the registered and runtime values privately character for character |
| Private callback routing unavailable or ineligible | Before an operator can complete OAuth enrollment | Confirm Google accepts the callback host before building private routing because a private IP, internal suffix, or Tailscale-only hostname may be rejected even when routing works |
| Secret format or required runtime activation not approved | Before generating the master key, MCP token, database token, or production OAuth material | Wait for the relevant merged format and activation requirements plus explicit owner approval, then use the approved secret manager |
| Private network reachability unavailable | Before Hermes, OAuth callback traffic, private health checks, or database egress can work | Validate private DNS, routing, firewall, TLS, and egress policy using synthetic endpoints and sanitized results |
| GitHub Actions disabled or owner permission missing | Before a manual release can be dispatched | Enable Actions or obtain the required repository permission through the repository owner without creating a personal token for the workflow |
| Immutable releases not confirmed | Immediately before release dispatch | Open `Settings > Releases`, confirm immutable releases are enabled, and do not dispatch if they are not |
| Failed `ci-required` | Before release dispatch | Resolve the failed check through a focused issue and wait for a passing current-main run |
| Stale or non-`main` commit SHA | At release dispatch and throughout publication | Use the full current `main` SHA and restart planning if `main` changes before dispatch |
| Reused version | At release dispatch | Select a new approved canonical version only after confirming no release, tag, draft, or previous attempt owns it |
| Retained failed release state | After a release workflow failure or cancellation | Preserve the draft, tag, assets, and attestations and resolve them through a separate approved issue without rerunning or deleting state |

## Provider documentation freshness

Provider user-interface labels, permissions, quotas, verification rules, token lifetimes, and recovery terms can change.
When the corresponding implementation issue becomes active, the owner must recheck the current official [Google OAuth 2.0 policies](https://developers.google.com/identity/protocols/oauth2/policies), [Google OAuth 2.0 overview and token behavior](https://developers.google.com/identity/protocols/oauth2), [Gmail scope reference](https://developers.google.com/workspace/gmail/api/auth/scopes), [GitHub manual workflow documentation](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow), [GitHub immutable releases documentation](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/using-immutable-releases-and-tags-to-manage-your-actions-releases), and [Turso documentation](https://docs.turso.tech/).
Names and navigation paths shown in this runbook describe the current operating procedure and are not guarantees that a provider will retain the same interface or policy.

## Credential handling rule

Agents never need and must never receive a credential value.
Do not paste a token, OAuth client JSON file, client secret, encryption key, session cookie, authorization header, private endpoint, real account identifier, or production URL into a task, issue, pull request, commit, log, screenshot, or chat message.
Do not ask an agent to run a command that would print a secret.
Credential values belong only in the approved runtime secret store.
Explicitly non-secret endpoint configuration may use the approved runtime configuration store.
Never store credential values in plain service files, unit files, tracked or untracked environment files, command arguments, or repository files.
InboxGate YAML contains environment-variable names only, never their values.
`inboxgate account add` resolves its YAML-selected Turso, Google, and encryption environment-variable names.
`inboxgate account list`, `account pause`, and `account resume` resolve only the selected Turso URL and optional token names.
`inboxgate account revoke` resolves the selected encryption key only after it has won and separately observed a durable revoked-attempting claim and a fresh read proves an encrypted credential is present.
Live remote Turso endpoints and bearer tokens remain rejected, so these command paths are for credential-free literal-loopback validation only until a later activation decision and explicit owner approval.
Configuration validation and effective output, capabilities, doctor, and the health-only service do not resolve those values, and no command resolves the selected MCP token name.
It reads only `INBOXGATE_CONFIG` for configuration-path selection when that variable is explicitly set.

The `_env` names below are compiled defaults, not fixed schema names.
Schema v1 lets each `_env` field select a different valid environment-variable name.
The owner must inject each runtime value under the exact name in the validated YAML.
`INBOXGATE_CONFIG` is a separate configuration-path selector and is not a YAML `_env` field.

| Compiled default or selector | Kind | Intended value owner | Needed now |
| --- | --- | --- | --- |
| `INBOXGATE_CONFIG` | Separate path selector | Runtime operator | Optional for selecting a configuration path |
| `TURSO_DATABASE_URL` | Compiled `_env` default | Runtime secret store | No |
| `TURSO_AUTH_TOKEN` | Compiled `_env` default | Runtime secret store | No |
| `GOOGLE_OAUTH_CLIENT_ID` | Compiled `_env` default | Runtime secret store | No |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Compiled `_env` default | Runtime secret store | No |
| `GOOGLE_OAUTH_REDIRECT_URL` | Compiled `_env` default | Runtime configuration store | No |
| `INBOXGATE_MCP_TOKEN` | Compiled `_env` default | InboxGate and the approved Hermes secret store | No |
| `INBOXGATE_MASTER_KEY` | Compiled `_env` default | Runtime secret store with an independent backup | No |

The compiled defaults and any names selected in YAML are public configuration policy, but their values and presence remain sensitive runtime state.
`GOOGLE_OAUTH_REDIRECT_URL` is operational endpoint configuration rather than a credential, but it can reveal private network details and must still be injected outside tracked YAML.
Do not create an untracked `.env` file in the repository as a convenience.

## Step-by-step Turso preparation after architecture acceptance

Do not begin this section until ADR 0004 is merged and an active implementation issue explicitly authorizes production setup.
The implementation and its credential-free tests must pass before live Turso access is considered.

1. Read the accepted replacement ADR and confirm its exact driver or protocol version, transport controls, engine requirements, and rollback plan.
2. Sign in to the owner-controlled Turso organization and create a new Turso Database using the engine required by the accepted ADR.
3. Choose the approved region and record only non-identifying policy facts such as engine type, region class, quota tier, and recovery window in the private deployment runbook.
4. Review the current [Turso documentation](https://docs.turso.tech/), [durability guarantees](https://docs.turso.tech/cloud/durability), and [point-in-time recovery guidance](https://docs.turso.tech/features/point-in-time-recovery).
5. Create a least-privilege database token through the Turso owner interface only after the implementation documents the exact required permissions and rotation procedure.
6. Put the database URL into the approved runtime secret store under the validated configuration name (default: `TURSO_DATABASE_URL`).
7. Put the database token into the approved runtime secret store under the validated configuration name (default: `TURSO_AUTH_TOKEN`).
8. Do not place either value in YAML, shell history, a command argument, an issue, or an agent message.
9. Confirm privately that the production URL uses verified HTTPS and that no cleartext remote endpoint is accepted.
10. Run only the approved redacted connectivity or migration command documented by the future storage issue.
11. Share the command name, exit status, and sanitized error category if help is needed, but replace identifiers, paths, hosts, queries, and values with fixed placeholders.
12. Perform the documented recovery drill before production sign-off and record sanitized evidence in the approved issue.

If the accepted architecture cannot pass its credential-free contract suite, stop before account setup and return the problem to architecture review.
Live credentials must never be used to compensate for an untestable boundary.

## Step-by-step Google OAuth and Gmail preparation

Do not begin consent or account enrollment until the OAuth enrollment feature is merged and the owner explicitly approves access to the selected test account.
InboxGate must request the identity-only `openid` scope plus only the Gmail read-only data scope and must never mutate a mailbox.
Google currently classifies `https://www.googleapis.com/auth/gmail.readonly` as a Restricted scope.
Audience eligibility, verification exemptions, and security-assessment applicability must be rechecked against current Google policy when the OAuth issue becomes active.

1. Choose an owner-controlled Google Cloud project and determine whether the consent audience is internal to a Google Workspace organization or external.
2. Enable the Gmail API in that project by following the [Gmail API guide](https://developers.google.com/workspace/gmail/api/guides).
3. Configure the OAuth consent screen with the minimum information required by Google.
4. Request `openid https://www.googleapis.com/auth/gmail.readonly`, where `openid` supplies stable identity and `gmail.readonly` is the sole Gmail data scope, as described in the [Gmail authorization scope reference](https://developers.google.com/workspace/gmail/api/auth/scopes).
5. Recheck the current [Google OAuth 2.0 policies](https://developers.google.com/identity/protocols/oauth2/policies) and [Restricted scope verification guidance](https://support.google.com/cloud/answer/13464321?hl=en) for the selected audience and use case.
6. Determine whether current rules require verification, a Restricted scope security assessment for server-side storage or transmission, an approved exemption, Workspace administrator approval, or a testing-user limit.
7. When required, prepare an accurate public homepage and privacy policy on an owned domain that is verified and authorized through Google controls.
8. Use separate owner-controlled testing and production projects when current Google rules or the approved rollout require that separation.
9. If the app remains in testing mode, add only explicitly approved test users through the Google owner interface and plan for the current refresh-token lifetime.
10. Before choosing private routing, validate the proposed redirect URI against the current [Google web-server OAuth rules](https://developers.google.com/identity/protocols/oauth2/web-server).
11. Under the current rules, require an exact redirect URI match, HTTPS except for permitted literal localhost test cases, no raw non-localhost IP address, a host on a public suffix, and an owned or authorized domain.
12. Treat a private IP, internal suffix, or Tailscale-only hostname as potentially ineligible even when it is privately reachable.
13. After merge and explicit approval, create only a confidential Web application OAuth client.
14. Register the exact accepted callback URL documented by that implementation and reject wildcard or fallback callback URLs.
15. Put the client ID into the approved runtime secret store under the validated configuration name (default: `GOOGLE_OAUTH_CLIENT_ID`).
16. Put the client secret into the approved runtime secret store under the validated configuration name (default: `GOOGLE_OAUTH_CLIENT_SECRET`).
17. Inject the exact callback URL outside tracked YAML through the runtime configuration store under the validated configuration name (default: `GOOGLE_OAUTH_REDIRECT_URL`).
18. Start enrollment only through `inboxgate account add` after database runtime activation and explicit owner approval, then confirm that the browser displays the expected project, read-only scope, and selected account.
19. Authorize each Gmail or Google Workspace account separately.
20. Verify through the future redacted account-listing command that the account is enrolled without sharing the account address, Google subject ID, token, or browser output.
21. Revoke the grant from the Google account security controls if the displayed project, callback, scope, or account is unexpected.

An OAuth client secret does not replace the per-account authorization flow.
An access token or refresh token must never be copied from the service for troubleshooting.

## Step-by-step encryption-key preparation

The accepted format is defined by [ADR 0007](adr/0007-versioned-provider-credential-encryption.md).
The one-shot `account add` command resolves the selected key after its credential-free loopback storage gate, and confirmed `account revoke` resolves it only after a proven revoked-attempting claim and fresh encrypted-credential presence.
Do not generate a production key until a later approved runtime issue supplies the exact private secret-manager workflow, rotation command, durable-record verification, and explicit owner approval.

1. In the approved deployment secret manager, use its cryptographically secure binary generator to create one 32-byte AES key without exposing its value to a terminal, clipboard, log, file, issue, pull request, chat, or agent.
2. Choose a non-secret key identifier that matches `[a-z][a-z0-9_-]{0,31}` and does not encode an account, person, host, date of birth, provider project, or secret-derived value.
3. Have the secret manager construct the canonical value `igk1:<active-key-id>=<43-character-unpadded-raw-URL-base64-key>` without printing it.
4. Store the complete canonical value only under the exact environment-variable name selected by the validated YAML, whose compiled default is `INBOXGATE_MASTER_KEY`.
5. Keep an independently protected recovery copy outside Turso and outside the InboxGate host.
6. Restrict read access to the InboxGate runtime identity and designated recovery operators.
7. For rotation, generate a new unique 32-byte key and make it the first active entry while retaining every prior key as a decrypt-only entry sorted bytewise by key identifier.
8. Keep the keyring to at most eight unique identifiers, eight unique key values, and 620 bytes without padding or whitespace.
9. Run the future bounded rotation operation and verify after a fresh process restart that every durable credential decrypts under the intended retained key set before removing any old key.
10. Roll back by restoring the previously backed-up canonical keyring and application version together, then verify decryption before resuming enrollment or synchronization.
11. Recover a replacement host by restoring the database and exact protected keyring independently, then complete the future redacted restart and credential-read checks.
12. Share only the non-secret key identifier, command name, exit status, and sanitized fixed error category when evidence is required.

Never share a key value, encoded key, hash, fingerprint, prefix, suffix, length-derived sample, or secret-manager export.
The current code has no operator rotation command and no live credential path, so these instructions define the required future owner action rather than authorizing it now.

Loss of this key could make encrypted OAuth credentials unrecoverable.
Exposure of this key could compromise every stored provider credential encrypted by it.

## Step-by-step MCP and Hermes preparation

Do not connect Hermes until the authenticated streamable HTTP MCP transport and its bounded tool contracts are merged and pass protocol tests.

1. Select a private network path between the Hermes host and InboxGate.
2. Keep the MCP endpoint off the public internet and use the exact route configured by `mcp.path`.
3. Generate an independent high-entropy bearer token through the approved secret manager after the MCP implementation defines its minimum format.
4. Store the server copy in the InboxGate runtime secret store under the validated configuration name (default: `INBOXGATE_MCP_TOKEN`).
5. Store the client copy only in the approved Hermes runtime secret store without sending it to an agent.
6. Do not reuse a Google token, Turso token, encryption key, network enrollment key, or Vikunja credential.
7. Inject the non-secret private endpoint through the approved Hermes runtime configuration store.
8. Configure Hermes with the bounded MCP tool set documented by the merged implementation.
9. Confirm that Hermes can call `system_capabilities` and only the explicitly enabled mail tools.
10. Confirm that arbitrary Gmail requests, raw SQL, shell execution, URL fetching, OAuth enrollment, and direct Vikunja operations are unavailable.
11. Run the synthetic end-to-end review flow before any live email is exposed.

Email returned through MCP is untrusted data and cannot authorize a tool call, credential disclosure, policy change, or mailbox mutation.

## Step-by-step private deployment preparation

Deployment remains owner-approved work and is not included in the current repository foundation.

1. Choose a privately administered host and document the runtime owner, firewall owner, TLS owner, backup owner, and incident contact in a private runbook.
2. Run InboxGate as an unprivileged dedicated identity with a read-only application filesystem except for explicitly required state.
3. Inject credential values only through the approved runtime secret store and prevent them from appearing in process arguments, unit files, images, logs, or repository files.
4. Bind the service only to an approved private interface or place it behind an approved private reverse proxy.
5. Apply a default-deny firewall and allow only the required private Hermes, operator, and health-probe paths.
6. Terminate TLS at an approved boundary and verify certificate and hostname checks between every non-loopback hop.
7. Keep health details, OAuth administration, MCP, and operator routes off the public internet.
8. Set resource limits, restart policy, log retention, clock synchronization, and graceful shutdown behavior according to the future hardened deployment runbook.
9. Restore the service on a fresh host using only the repository, approved runtime secrets, and the accepted remote database recovery procedure.
10. Complete synthetic smoke tests before authorizing live provider access.

The current `serve` command exposes only bounded process liveness and readiness.
It does not prove database, migration, scheduler, Gmail, OAuth, MCP, or account readiness.

## Step-by-step manual GitHub release

InboxGate already has a manual GitHub Actions release workflow.
It uses GitHub's automatic workflow token and does not require a personal access token, GitHub App secret, Turso credential, Google credential, or deployment credential.
A release is a deliberate owner operation and is never created automatically by merging a pull request.
Release publication is not deployment approval and does not imply that Gmail, OAuth, Turso, persistence, MCP, or production operation is supported.

1. Open the repository's Actions tab in GitHub.
2. Select the `Release` workflow.
3. Confirm that the target commit is the current `main` commit and that its latest completed `ci-required` check passed.
4. Open `Settings > Releases` in another tab and confirm immediately before dispatch that immutable releases are enabled.
5. Return to the workflow, select `Run workflow`, and choose `main`.
6. Enter an unused canonical version such as `v0.1.0` only when that release is approved.
7. Enter the full lowercase 40-character SHA for the reviewed `main` commit.
8. Submit the workflow once.
9. Inspect the completed run, generated release, exact asset set, attestations, checksums, and tag target.
10. Record the release URL, version, commit, and verification evidence in the approved release issue.

Do not rerun a failed publication with the same version and do not publish locally around a workflow failure.
The workflow intentionally retains a failed draft, reserved tag, asset, or attestation for investigation.
Follow the complete [release guide](releases.md) for failure handling and consumer verification.

## Safe evidence to share

When an implementation issue asks for owner evidence, share the smallest sanitized fact that proves the prerequisite.

Safe examples include these items.

- The provider setup step that was completed, without an account, organization, project, database, or host identifier.
- A documented engine type, region class, quota tier, or recovery window that contains no private identifier.
- A command name and exit code with all output omitted or sanitized.
- A fixed error category from InboxGate after removing URLs, paths, headers, queries, account data, provider data, and values.
- A public GitHub workflow, issue, pull request, commit, or release URL.
- A screenshot cropped to the relevant control after removing browser profiles, account names, emails, IDs, private domains, endpoints, tokens, QR codes, and notifications.

Use placeholders such as `<redacted-account>`, `<redacted-host>`, and `<redacted-id>` instead of partial real values.
Do not share a prefix, suffix, length, hash, fingerprint, or encoded form derived from a secret.
Do not share provider-generated JSON, environment dumps, shell history, HTTP traces, database connection strings, authorization headers, or full browser screenshots.

## If a credential is disclosed

Treat any accidental disclosure as a compromise even if the message, log, branch, or file appears private or is later removed.

1. Stop using the affected credential and stop the operation that exposed it.
2. Revoke or rotate it at the authoritative provider or secret manager.
3. Update the approved runtime secret store directly without sending the replacement to an agent.
4. Restart or redeploy only the components that need to acquire the replacement.
5. Review provider audit records for unexpected use and preserve a sanitized incident timeline.
6. Report repository-related exposure through the private process in [SECURITY.md](../SECURITY.md), never through a public issue.
7. Open a focused approved remediation issue if code, logging, workflow, or documentation allowed the disclosure.
8. Do not rely on deleting a message, rewriting Git history, or removing a file as proof that the old value is safe.

Rotate a Turso token through Turso, rotate a Google OAuth client secret through Google Cloud, revoke affected per-account grants through Google account security controls, and rotate an MCP token at both endpoints.
If the value selected by `encryption.master_key_env` (default: `INBOXGATE_MASTER_KEY`) is exposed or lost after encrypted records exist, stop and follow the accepted key-recovery and re-encryption procedure because replacing the environment value alone can destroy access or leave old ciphertext exposed.

## What to send an agent when a prerequisite is ready

Use a value-free statement like this one.

```text
The owner prerequisite for <area> is complete.
The approved secret store contains the required values under the exact environment-variable names selected by the validated YAML.
No credential value is included in this message.
The sanitized provider or workflow evidence is <public link or non-identifying status>.
Proceed only with the credential-free checks defined by issue <number>.
```

If an implementation genuinely requires a live check, the issue must first define the exact command, redaction behavior, least privilege, cleanup, and owner approval boundary.
The owner enters values directly into the controlled runtime environment and the agent still does not receive or print them.
