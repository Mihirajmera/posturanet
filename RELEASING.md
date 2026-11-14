# Releasing PosturaNet

The public repo is `github.com/Mihirajmera/posturanet`; this folder is its root. Releases go to
PyPI through **trusted publishing**: GitHub proves the workflow's identity to PyPI, so no API
token exists to leak, and PyPI stores signed build attestations.

## One-time setup (a maintainer does these by hand)
1. **PyPI:** sign in at pypi.org → Account → Publishing → *Add a new pending publisher*:
   project `posturanet`, owner `Mihirajmera`, repository `posturanet`, workflow `release.yml`,
   environment `pypi`. This reserves the name until the first upload.
2. **GitHub repo:** Settings → Environments → New environment `pypi`. Add yourself as a
   required reviewer, so every publish waits for a click.
3. **Branch protection** on `main`: require the `CI` checks.

## Each release
1. Update `version` in `pyproject.toml`, `src/posturanet/__init__.py`, the Action's default
   `version` in `action.yml` and `action/action.yml`, `plugin/.claude-plugin/plugin.json` and the Action tag in
   `integrations/github/posturanet-check.yml`; re-record the demos (`python docs/media/make.py`); move CHANGELOG `[Unreleased]` to the new version.
2. Merge to `main` with CI green (CI builds the wheel, runs `twine check` and installs it).
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. Approve the `pypi` deployment in the Actions run. The workflow checks the tag matches the
   version, builds, publishes, and creates the GitHub release with the files attached.
5. Check: `pip install posturanet==X.Y.Z && posturanet --version`.

A version on PyPI can never be replaced, only yanked. If something is wrong, release the next
patch version.
