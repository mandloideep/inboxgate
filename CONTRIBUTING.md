# Contributing to InboxGate

Thank you for helping improve InboxGate.

## Before starting

Search open and closed issues and pull requests for existing work.
Open a planned-change issue before creating an implementation branch.
Security vulnerabilities must be reported privately as described in [SECURITY.md](SECURITY.md).

The project works on one implementation pull request at a time.
A maintainer will mark the selected issue `status:in-progress` before implementation begins.
Create the branch from current `origin/main` as `issue-<number>-<slug>`.

## Development workflow

Follow red, green, and refactor for every production behavior.
Keep one concern in each pull request and avoid unrelated cleanup.
Do not add a direct dependency without an accepted architecture decision record using [docs/adr/template.md](docs/adr/template.md).
Use synthetic test data and never use live credentials or private email content.

Run the complete local gate before requesting review:

```sh
make check
git diff --check
git diff origin/main...HEAD
```

`make check` installs the pinned `govulncheck` release into the ignored `.tools` directory when necessary.
The vulnerability scan needs access to the public Go vulnerability database.

## Pull requests

Follow [docs/development-workflow.md](docs/development-workflow.md).
Use a concise `type(scope): outcome` title.
Begin the description with the user-visible problem, then briefly explain the solution.
Link the issue with `Closes #<number>` and report validation, dependency impact, threat-model impact, deletion requests, and visual evidence when a visible interface changes.

All CI checks and review conversations must be resolved before squash merge.
Do not add an AI assistant as a co-author.
Do not edit `CHANGELOG.md`; releases use generated notes.

## Documentation style

Use the plain hyphen character instead of an em dash.
In long Markdown files, put each complete sentence on its own physical line.
Keep examples free of secrets, personal data, account identifiers, and production endpoints.

## Deletions

Contributors and agents do not delete, rename, truncate, or replace pre-existing files.
Record proposed removals in [DELETION_REQUESTS.md](DELETION_REQUESTS.md) for the repository owner.
Temporary files created by the same contributor inside an isolated temporary directory are exempt.
