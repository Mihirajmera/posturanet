## What and why

<!-- One or two sentences. Link the issue or FR id. -->

## Checklist (AGENTS.md §1.7 and §1.10)

- [ ] Tests added; fixtures are synthetic
- [ ] `pytest -q`, `ruff check`, `ruff format --check`, `mypy src` pass
- [ ] No new AWS call, or it is read-only, allowlisted and in the generated IAM policy
- [ ] No new data leaves the process
- [ ] CHANGELOG entry under `[Unreleased]`
- [ ] Docs updated if behavior, schemas or scope changed
