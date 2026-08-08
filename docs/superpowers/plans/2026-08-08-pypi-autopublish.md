# PyPI Auto-Publish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `.github/workflows/publish.yml` in `miiidev/blacklight-cli` that runs on `v*` tag pushes and gates (version-sync → pytest → build) then publishes to live PyPI via Trusted Publishing (OIDC), plus the operational release steps.

**Architecture:** Single GitHub Actions workflow. One job with four steps in a strict order; any step failing aborts before PyPI is touched. Version sync is a small inline Python script comparing `blacklight/__init__.py` vs `pyproject.toml`.

**Tech Stack:** GitHub Actions (ubuntu-latest), Python 3.12, setuptools build (`python -m build`), `pypa/gh-action-pypi-publish@release/v1`.

## Global Constraints

- Workflow file path must be `.github/workflows/publish.yml` (python classifier: None — it's config, not a module).
- Trigger: tag pushes matching `v*` only. Regular `main` pushes must NOT trigger it.
- Auth: Trusted Publishing (OIDC) — `id-token: write`, environment `pypi`. No secrets in the workflow.
- Upload targets live PyPI; artifacts are the sdist+wheel in `dist/`.
- Gate order fixed: version sync → tests → build → publish; a failure aborts before upload.
- Version sync rule (verbatim from spec): `blacklight/__init__.py`'s `__version__` string must equal `project.version` in `pyproject.toml`.
- Tests gate: `pip install -e ".[dev]"` then `python -m pytest` (currently 294 passing).
- Repo convention: version is static, bumped in the two files by hand; the workflow never changes versions or creates tags.
- Repo/publish owner for OID: `miiidev`.

---

### Task 1: Create the publish workflow

**Files:**
- Create: `.github/workflows/publish.yml`

**Interfaces:**
- Consumes: (none — standalone repository-level config)
- Produces: workflow named `publish`; one job `publish` on environment `pypi` with steps: checkout, setup-python, version-sync guard, tests, build, upload.

**No TDD here** — a workflow YAML has no unit tests; verification is a YAML parse (Step 2) plus the real fire via the tag push at Task 3.

- [ ] **Step 1: Write the workflow file**

```yaml
name: publish

on:
  push:
    tags:
      - "v*"

permissions:
  contents: read

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Check version sync
        run: |
          python - <<'EOF'
          import re, sys, tomllib
          from pathlib import Path
          init = Path("blacklight/__init__.py").read_text()
          m = re.search(r'__version__\s*=\s*"([^"]+)"', init)
          pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8-sig"))
          if not m or m.group(1) != pyproject["project"]["version"]:
              print(
                  f"version mismatch: __init__={m.group(1) if m else '(not found)'} "
                  f"pyproject={pyproject['project']['version']}"
              )
              sys.exit(1)

      - name: Install and test
        run: |
          python -m pip install -e ".[dev]"
          python -m pytest --tb=short

      - name: Build sdist and wheel
        run: |
          python -m pip install build
          python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

- [ ] **Step 2: Parse-check the YAML**

Run (creates no files):

```powershell
python -c "import yaml; d = yaml.safe_load(open('.github/workflows/publish.yml', encoding='utf-8')); print('jobs:', list(d['jobs']), '| env:', d['jobs']['publish'].get('environment'))"
```

If `yaml` is missing, `pip install pyyaml` first.

Expected: `jobs: ['publish'] | env: pypi`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/publish.yml
git commit -m "ci: add PyPI trusted-publishing workflow on v* tags"
```

### Task 2: Push everything to origin

**Files:** (none — repository state)

**Interfaces:**
- Consumes: Task 1's committed workflow (must be on `main` when tags are pushed).
- Produces: `origin/main` containing the workflow — precondition for the workflow ever running.

- [ ] **Step 1: Push main**

```bash
git push origin main
```

Expected: succeeds, output shows 10 commits ahead → 0 (features, fix, spec, bump, ci).

### Task 3: Release v0.3.1 (operational, user-assisted)

**Files:** (none — operations only)

**Interfaces:**
- Consumes: workflow on `origin/main` (Task 2), user's one-time PyPI publisher entry.
- Produces: `blacklight-cli==0.3.1` on live PyPI; tag `v0.3.1` on origin.

- [ ] **Step 1: User sets up Trusted Publishing in PyPI (two-minute, UI only):**

1. Go to `https://pypi.org/manage/project/blacklight-cli/settings/publishing/` while signed in as the project owner.
2. "Add a new pending publisher": owner `miiidev`, repository `blacklight-cli`, workflow name `publish.yml`, environment `pypi`. Save.
3. Read back: a pending publisher entry appears for this workflow.

- [ ] **Step 2: Tag and push the release**

```bash
git tag v0.3.1
git push origin v0.3.1
```

Expected: the Actions run at https://github.com/miiidev/blacklight-cli/actions shows the workflow from the tag, all four steps go green.

- [ ] **Step 3: Verify the release**

```powershell
python -m pip install --upgrade blacklight-cli
blacklight --version
```

Expected: prints `0.3.1`; also `pip show blacklight-cli` shows Version 0.3.1 from PyPI.

**If the publish step fails with `400 ... already exists` style errors:** the version made it to PyPI and can't be reused — bump both `__init__.py` and `pyproject.toml`, commit, tag `v0.3.2`, push. (Spec: "No version reuse.")