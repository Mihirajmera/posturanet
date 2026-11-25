# Contributing to PosturaNet

Thanks for helping. Read [AGENTS.md](AGENTS.md) first: its golden rules apply to every change,
whether a person or an AI agent writes it.

## Set up

```bash
python -m venv .venv && . .venv/bin/activate    # Windows Git Bash: . .venv/Scripts/activate
pip install -e ".[dev]"
pytest -q
ruff check src tests && ruff format --check src tests && mypy src
```

## Before you open a PR

- Open an issue first for anything larger than a bug fix, so we can agree on scope
  ([PRD §1.4 scope rules](AGENTS.md#14-scope-discipline)).
- Add tests. Fixtures must be synthetic: RFC 5737 / RFC 1918 addresses, account `123456789012`,
  never real findings, logs or state.
- No new AWS call unless it is read-only and in the allowlist and the generated IAM policy.
- Keep user-facing text in line with [docs/04_DESIGN_SYSTEM.md](docs/04_DESIGN_SYSTEM.md).
  Never write "proven safe", "guaranteed", "100% safe" or "zero risk".
- Add a CHANGELOG entry under `[Unreleased]`.
- Open the PR against `test`, not `main`.

## Adding a settings control

Most contributions are new rows in `src/posturanet/configfix/catalog.json`. Follow architecture
§14.1: a row is only allowed if the setting can't remove access or traffic, or it carries
`risk: medium` and a note saying what to check before merging.

## License

PosturaNet is under FSL-1.1-ALv2 (see [LICENSE.md](LICENSE.md)). By contributing you agree your
contribution is licensed the same way.
