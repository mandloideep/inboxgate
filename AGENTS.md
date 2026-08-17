# InboxGate agent instructions

These instructions apply to every agent working in this repository.

## Product invariants

- InboxGate is a deterministic email data service, not an autonomous agent.
- The first release supports Gmail and Google Workspace only.
- Gmail access is read-only.
- Never send, reply, forward, archive, delete, label, or mark Gmail messages as read.
- Hermes may access InboxGate only through the bounded MCP surface defined by the product specification.
- Never expose raw SQL, arbitrary Gmail requests, shell execution, URL fetching, direct Vikunja operations, or a public general-purpose REST API.
- Do not add A2A, a generic provider framework, a plugin system, a web application, or a marketing site without an approved issue.
- Configuration contains secret environment-variable names only and never secret values.
- Treat email metadata, message content, OAuth data, logs, and MCP results as sensitive.

## Delivery lifecycle

1. Synchronize and inspect `origin/main`, then search open and closed issues and pull requests for duplicate work.
2. Use the planner agent in read-only mode to confirm one clear problem, acceptance criteria, non-goals, security impact, dependency impact, capability-surface impact, validation, and deletion requests.
3. Create the issue before the branch.
4. Allow only one issue labeled `status:in-progress` and one open implementation pull request.
5. Create `issue-<number>-<slug>` from current `origin/main`.
6. Assign all repository writes to one implementer agent.
7. Keep every other agent read-only while implementation is active.
8. Follow red, green, and refactor for every production behavior.
9. Before opening a pull request, check for an existing pull request for the branch, inspect `origin/main...HEAD`, run `git diff --check`, and exclude unrelated changes.
10. Use a real pull request with a `type(scope): outcome` title and one concern only.
11. Run correctness, security, and test reviews with three separate read-only agents.
12. Return valid findings to the sole implementer and repeat validation and review after changes.
13. Squash merge only when the branch is current, `ci-required` passes, all conversations are resolved, and all material findings are closed.
14. Validate a fresh `main` after merge and record the issue, pull request, commit SHA, and check evidence before starting another task.

The orchestrating agent owns issue, branch, pull request, review, merge, and post-merge coordination.
The implementer is the sole writer and must not create or merge its own pull request.

## Engineering rules

- Begin bug fixes by reproducing the end-user failure as closely as possible.
- Begin every new production behavior with a failing test and preserve the red evidence.
- Prefer the Go standard library and explicit, narrow interfaces.
- Run `make check` and `git diff --check` before requesting review.
- Fix discovered correctness, security, lint, test, and flakiness problems within the active concern.
- Use synthetic fixtures only.
- Never use live credentials, real email, private domains, account identifiers, Tailscale names, or production URLs in code, tests, documentation, issues, or logs.
- Never add an assistant or agent as a commit co-author.
- Never create or edit `CHANGELOG.md` manually.
- Never use the em dash character.
- In long Markdown files, put each complete sentence on its own physical line.

## Dependencies

Every new direct dependency requires an accepted architecture decision record before it is added.
The record must cover the need, alternatives, exact version, complete transitive dependency impact, license, advisory status, maintenance status, and removal plan.
Pin direct dependencies, CI tools, GitHub Actions, package-manager lockfiles, and container base images to immutable versions.

## Security review triggers

Update `docs/threat-model.md` when a change affects trust boundaries, authentication, authorization, secret handling, encryption, external requests, stored data, user-controlled content, MCP tools, or network exposure.
Never weaken Gmail read-only scope or the prompt-injection boundary.
Security reports belong in GitHub private vulnerability reporting and never in public issues.

## Deletion policy

Do not delete, rename, truncate, or replace a pre-existing file.
Record the path, reason, replacement, impact, recoverability, related issue, and owner status in `DELETION_REQUESTS.md`.
Only the repository owner performs the removal.
Temporary files created by the same agent inside an isolated temporary directory are exempt.

## Code review rules

- Flag any path that could mutate Gmail state.
- Flag any secret value accepted from configuration or emitted to output.
- Flag arbitrary Gmail, SQL, shell, URL-fetching, Vikunja, or capability access.
- Flag synchronization cursor advancement that is not transactional with durable writes.
- Flag unbounded message content, pagination, retries, concurrency, backfill, or MCP output.
- Flag user-controlled email content that could be interpreted as trusted instructions.
