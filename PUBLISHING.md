# Publishing rlsgrid

This project ships to PyPI via **trusted publishing** — no API token lives
in the repo. A GitHub Actions workflow exchanges its OIDC identity for a
short-lived upload credential.

## One-time setup (per owner of the PyPI project)

1. Build the project locally to claim the name on PyPI:

   ```bash
   python -m pip install --upgrade build twine
   python -m build
   python -m twine upload dist/*
   ```

   This first upload uses a normal PyPI API token. From now on the GitHub
   workflow takes over.

2. On <https://pypi.org/manage/project/rlsgrid/settings/publishing/> add a
   trusted publisher:
   - Owner: `matte97p`
   - Repository: `rlsgrid`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`

3. On <https://github.com/matte97p/rlsgrid/settings/environments> create
   an environment called `pypi`. Add a protection rule restricting it to
   tags matching `v*.*.*` so a stray branch push cannot publish.

## Cutting a release

```bash
# 1. Bump the version in pyproject.toml and CHANGELOG.md.
$EDITOR pyproject.toml src/rlsgrid/__init__.py CHANGELOG.md

# 2. Commit and tag.
git commit -am "release: v0.2.0"
git tag v0.2.0
git push origin main --tags
```

The `release.yml` workflow then:
1. Builds the sdist and wheel.
2. Verifies the version in `pyproject.toml` matches the tag.
3. Uploads to PyPI via OIDC.

## Pre-release dry run

```bash
python -m build
python -m twine check dist/*
```
