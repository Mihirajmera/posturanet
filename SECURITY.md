# Security policy

PosturaNet runs with read access to your AWS account and write access to your repositories, so
we treat security reports as the top priority.

## Reporting a vulnerability

Email **founderposturanet@gmail.com** with "security" in the subject. Please don't open a public
issue. Include the version (`posturanet --version`), what you ran, and what happened. Use
synthetic data: never send real findings, account ids, Terraform state or logs.

We reply within 3 business days, and tell you when a fix ships. We credit reporters in the
CHANGELOG unless you'd rather we didn't.

For vendor security reviews, start with the pre-filled answers in
[docs/security-questionnaire.md](docs/security-questionnaire.md).

## Supported versions

Only the latest release on PyPI gets security fixes. Upgrade with `pip install -U posturanet`.

## Verifying a release

Every release from 0.5.4 on is built by `.github/workflows/release.yml` from the tagged commit:

- PyPI holds signed attestations for the wheel and sdist (trusted publishing, no stored token).
- The GitHub release has the wheel, the sdist and a CycloneDX SBOM
  (`posturanet-<version>.cdx.json`: the package and every dependency it installs), each with a
  signed build-provenance attestation. Check a downloaded file with:

  ```bash
  gh attestation verify posturanet-0.5.4-py3-none-any.whl --repo Mihirajmera/posturanet
  ```

## What is in scope

- Any way PosturaNet could make a mutating AWS call (golden rule 1 in [AGENTS.md](AGENTS.md)).
- Any way a fix PR could open after a failed or skipped check (fail-closed, NFR-1).
- Finding text, code comments or tool output that PosturaNet acts on as instructions.
- Data leaving your environment beyond the opt-in outcome share's five fields.
- Secrets reaching logs, PR bodies or an LLM prompt.
- The GitHub Action, the MCP server, the Claude Code plugin and `receiver/`.
