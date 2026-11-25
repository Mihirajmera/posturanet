# Security policy

PosturaNet runs with read access to your AWS account and write access to your repositories, so
we treat security reports as the top priority.

## Reporting a vulnerability

Email **founderposturanet@gmail.com** with "security" in the subject. Please don't open a public
issue. Include the version (`posturanet --version`), what you ran, and what happened. Use
synthetic data: never send real findings, account ids, Terraform state or logs.

We reply within 3 business days, and tell you when a fix ships. We credit reporters in the
CHANGELOG unless you'd rather we didn't.

## Supported versions

Only the latest release on PyPI gets security fixes. Upgrade with `pip install -U posturanet`.

## What is in scope

- Any way PosturaNet could make a mutating AWS call (golden rule 1 in [AGENTS.md](AGENTS.md)).
- Any way a fix PR could open after a failed or skipped check (fail-closed, NFR-1).
- Finding text, code comments or tool output that PosturaNet acts on as instructions.
- Data leaving your environment beyond the opt-in outcome share's five fields.
- Secrets reaching logs, PR bodies or an LLM prompt.
- The GitHub Action, the MCP server, the Claude Code plugin and `receiver/`.
