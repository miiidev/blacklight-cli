# Blacklight tokyo-night theme Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply Textual's built-in `tokyo-night` theme to the TUI and update the CLI palette constants so banner/progress/report accents match.

**Architecture:** Two independent, one-line-class changes. (1) `blacklight/tui/app.py` gets a class attribute `theme = "tokyo-night"` which Textual picks up for every TUI surface. (2) `blacklight/theme.py` color constants change to tokyo-night primary/secondary hex values; every consumer (banner gradient, progress, reports, console label) references these constants, so one edit re-colors them all. No layout, behavior, or engine changes.

**Tech Stack:** Python 3.11, Textual 8.2.x (built-in theme registry), pytest, rich.

## Global Constraints

- `blacklight/theme.py` constants: `PURPLE = "#BB9AF7"`, `CYAN = "#7AA2F7"`, `ACCENT = "#BB9AF7"`, `DIM = "#6b7280"` (DIM unchanged).
- `BlacklightApp` (in `blacklight/tui/app.py`) gains `theme = "tokyo-night"` as a class attribute.
- Severity colors (`SEVERITY_STYLE`), risk-gauge bands, banner text, and the hardcoded `[cyan]●` literal in `reporter.py` are explicitly OUT of scope.
- No user-configurable theming; no new dependencies.
- Design spec: `docs/superpowers/specs/2026-08-07-blacklight-tokyo-night-theme-design.md`.

---

### Task 1: CLI palette constants to tokyo-night

**Files:**
- Modify: `blacklight/theme.py:9-12`
- Test: `tests/test_theme.py`

**Interfaces:**
- Consumes: nothing (constants live in the same file).
- Produces: `blacklight.theme.PURPLE == "#BB9AF7"`, `blacklight.theme.CYAN == "#7AA2F7"`, `blacklight.theme.ACCENT == "#BB9AF7"`, `blacklight.theme.DIM == "#6b7280"` — later tasks and existing consumers (cli.py, reporter.py, console.py) rely on these names, not values.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_theme.py`:

```python
def test_palette_uses_tokyo_night_colors():
    assert theme.PURPLE == "#BB9AF7"
    assert theme.CYAN == "#7AA2F7"
    assert theme.ACCENT == "#BB9AF7"
    assert theme.DIM == "#6b7280"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_theme.py::test_palette_uses_tokyo_night_colors -v`
Expected: FAIL (current PURPLE is `#8b5cf6`, CYAN `#22d3ee`, ACCENT `#f0abfc`).

- [ ] **Step 3: Update the constants**

In `blacklight/theme.py`, change lines 9-12 to:

```python
PURPLE = "#BB9AF7"
CYAN = "#7AA2F7"
ACCENT = "#BB9AF7"
DIM = "#6b7280"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_theme.py -v`
Expected: all PASS, including the existing gradient/banner/gauge tests (no existing test pins the old hex values).

- [ ] **Step 5: Commit**

```bash
git add blacklight/theme.py tests/test_theme.py
git commit -m "feat: retint CLI palette to tokyo-night colors"
```

---

### Task 2: TUI runs on the tokyo-night theme

**Files:**
- Modify: `blacklight/tui/app.py:34-39` (the `BlacklightApp` class body, after `TITLE`)
- Test: `tests/test_tui.py`

**Interfaces:**
- Consumes: `blacklight.tui.app.BlacklightApp` (already imported in tests/test_tui.py as `from blacklight.tui.app import BlacklightApp`).
- Produces: `BlacklightApp.theme == "tokyo-night"` class attribute. No other code consumes it; Textual's app runner reads it internally.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_tui.py`:

```python
def test_tui_uses_tokyo_night_theme():
    from blacklight.tui.app import BlacklightApp
    assert BlacklightApp.theme == "tokyo-night"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_tui.py::test_tui_uses_tokyo_night_theme -v`
Expected: FAIL (`BlacklightApp` has no class attribute `theme` — Textual's `App` default `theme` lives on the instance base class as `textual-dark`; accessing it via the subclass may resolve the inherited class-level Reactive, which is not `"tokyo-night"`).

- [ ] **Step 3: Add the class attribute**

In `blacklight/tui/app.py`, inside `class BlacklightApp(App):`, right after `TITLE = "blacklight-cli console"` (line 38), add:

```python
    theme = "tokyo-night"
```

Do NOT touch `on_mount` or any other method. Textual applies the built-in theme by name; no `THEMES` registration is needed for built-ins.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_tui.py::test_tui_uses_tokyo_night_theme -v`
Expected: PASS.

- [ ] **Step 5: Run the full TUI test file**

Run: `python -m pytest tests/test_tui.py -q`
Expected: all PASS (12 tests). The existing tests drive the app via `run_test`; verify none fail from the theme swap (they shouldn't — no test asserts theme-dependent colors).

- [ ] **Step 6: Commit**

```bash
git add blacklight/tui/app.py tests/test_tui.py
git commit -m "feat: run the TUI on the tokyo-night theme"
```

---

### Task 3: Full verification and smoke

**Files:** none modified.

**Interfaces:**
- Consumes: everything from Tasks 1-2.

- [ ] **Step 1: Run the full suite**

Run: `python -m pytest -q`
Expected: 251 passed (249 existing + 2 new), 0 failed.

- [ ] **Step 2: Smoke the TUI launch**

Run: `python -c "import asyncio; from blacklight.tui.app import BlacklightApp; from blacklight import cli; app = BlacklightApp(execute_scan=cli.execute_scan, execute_web=cli.execute_web); app.run()"` — do not block; this step is a launch check only. If it renders without traceback for a few seconds, close it (Ctrl+C). Expected: TUI starts, surfaces tinted violet/navy.

- [ ] **Step 3: Smoke the CLI banner**

Run: `python -m blacklight.cli --help 2>&1 | Select-String -Pattern "blacklight-cli" | Select-Object -First 1`
Expected: the `blacklight-cli v0.3.0` line renders (colors not asserted — visual check that the gradient banner draws in the terminal).

- [ ] **Step 4: Note outcome for the controller**

Report: full suite count, both smoke results, and `git log --oneline -3`.
