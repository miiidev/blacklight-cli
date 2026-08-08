# PyPI Auto-Publish via GitHub Actions — Design

Date: 2026-08-08

Status: Approved for planning

## Problem

The user wants the new update (v0.3.1: TUI splash + fixes) published to PyPI
automatically — a push/tag should build the package, run the tests, and
upload it — without storing a PyPI token. Publishing currently requires
manual twine steps and keeping API tokens alive.

## Decisions (from brainstorming)

- **Trigger: tag push.** Pushing a git tag matching `v*` (e.g. `v0.3.1`).
  Regular pushes to `main` do not publish.
- **Auth: Trusted Publishing (OIDC).** No GitHub secrets or PyPI tokens.
  `pypa/gh-action-pypi-publish` with `id-token: write`; the user links the
  GitHub workflow to the PyPI project once in the PyPI web UI.
- **Gates: version-sync check, tests, build — one job, publish blocked by any
  failure.** No separate "release" GitHub Release artifact step (YAGNI).
- **Target: live PyPI.** No Test PyPI dry-run stage (YAGNI; easy follow-up).

## Approach

A single workflow file `.github/workflows/publish.yml`.

### Components

**Version-sync guard**

- Compares `blacklight/__init__.py`'s `__version__` against the
  `project.version` in `pyproject.toml`. Mismatch fails the workflow —
  version drift (both are bumped by hand today) must not silently ship a
  package whose metadata disagrees with `blacklight.__version__`.

**Test gate**

- `pip install -e ".[dev]"` then `python -m pytest` (currently 294 tests).
  Fails → no publish.

**Build**

- `pip install build`, `python -m build` → sdist + wheel.

**Publish (Trusted Publishing)**

- `pypa/gh-action-pypi-publish@release/v1`, environment `pypi`,
  `id-token: write`, default inputs (uploads the `dist/` artifacts).
  The environment name must match what the PyPI publisher entry declares.

## One-time PyPI setup (user, in the browser)

1. PyPI → `blacklight-cli` → **Settings → Publishing**.
2. "Add a new pending publisher": owner `miiidev`, repo `blacklight-cli`,
   workflow name `publish.yml`, environment `pypi`. Save.
3. Next `v*` tag push then publishes with no further action, ever.

## Error handling / constraints

- **No version reuse.** If publish fails after the version reached PyPI
  (build-tool, network, or workflow error), the same version can never be
  re-uploaded; the fix is bumping + tagging again (e.g. `v0.3.2`).
- A failing gate (version drift or tests) fails the workflow before anything
  reaches PyPI — no partial state, nothing to unpublish.
- Workflow only runs on tags; pushes to `main` remain pure GitHub-only
  (no side effects).

## Out of scope

- GitHub Release creation with release notes.
- Test PyPI staging pipeline.
- Automatic version bumping (tag drives version; bump remains manual in
  `__init__.py` + `pyproject.toml`).
- Publishing to GitHub Packages.