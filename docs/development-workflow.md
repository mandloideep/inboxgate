# Issue and pull request workflow

## File an issue

Search open and closed issues and pull requests before filing.
State one concrete problem in plain language and explain why it matters to a user or operator.
Do not lead with a list of files to change.

Every planned-change issue must define measurable acceptance criteria and explicit non-goals.
It must also state security impact, dependency impact, capability-surface impact, focused validation, and any requested deletion.
Use `No impact` only after considering each field.

Bad issue opening:

> Add config package, parser types, defaults, tests, and docs.

Good issue opening:

> Operators cannot detect misspelled settings before startup, so a typo can silently change intended behavior.
> InboxGate needs a strict validation command that rejects unknown configuration.

Only one issue may have `status:in-progress` at a time.
Create its implementation branch only after the issue exists.

## File a pull request

Before filing, check whether a pull request for the branch already exists.
Review the complete diff against `origin/main` and exclude unrelated working-tree changes.
Run `git diff --check` and the focused and full validation commands.

Follow recent repository title conventions.
Use `type(scope): outcome` when no clearer convention exists.
The title should explain why the change matters because it becomes the squash commit message.

Open the description with the original problem in simple language.
Then explain the solution briefly.
Do not lead with an implementation inventory.

Keep one concern per pull request.
If the description needs an unrelated `also`, split the work.
Link the issue with `Closes #<number>`.
Include focused validation, dependency impact, threat-model impact, deletion status, and useful visual evidence when visible UI changes.

Open a real pull request so review automation runs.
Do not use a draft unless the issue explicitly requires one.

## Review and merge

The orchestrator assigns three independent read-only reviews for correctness, security, and testing.
The sole implementation agent addresses accepted findings.
Review and CI repeat after material changes.

The orchestrator may squash merge only after `ci-required` passes, the branch is current, review conversations are resolved, and all material findings are closed.
After merge, validate fresh `main` and record the issue, pull request, merge commit, and final checks in the issue.
