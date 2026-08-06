# Blacklight tokyo-night theme

Date: 2026-08-07
Status: Approved (design review)
Branch: from `main` after Textual console TUI merge

## Problem

The tool's visual identity — a purple/cyan palette on near-black — is intended to
evoke a "blacklight" (ultraviolet) look. The Textual TUI currently uses Textual's
default `textual-dark` theme, and the CLI palette (`blacklight/theme.py`) uses an
ad-hoc purple/cyan that does not match any curated palette. The user wants the TUI
and CLI to share a coherent palette that reflects the "blacklight" name.

## Goal

- TUI runs on Textual's built-in `tokyo-night` theme (violet/periwinkle on deep
  navy-black — the closest built-in fit to a blacklight feel).
- CLI palette constants (`theme.PURPLE`, `theme.CYAN`, `theme.ACCENT`) are updated
  to tokyo-night's primary/secondary colors so banner, progress, and report
  accents match the TUI.
- Everything else stays as-is (severity colors, risk-gauge bands, layout, behavior).

## Non-goals

- No user-configurable runtime theming (env var / config flag). Hardcoded palette.
- No changes to severity colors (`SEVERITY_STYLE`), risk-gauge bands, or the
  `DIM` constant.
- No changes to layout, behavior, or any engine/CLI-command code.
- No changes to banner text.

## Changes

### 1. TUI theme (`blacklight/tui/app.py`)

Add a class attribute to `BlacklightApp`:

```python
theme = "tokyo-night"
```

Textual applies built-in theme `tokyo-night` (dark: true) to all TUI surfaces:
Header, sidebar borders, DataTable cursor/focus, buttons, ConfirmModal,
ProgressBar. No other TUI code changes; no CSS changes needed.

### 2. CLI palette (`blacklight/theme.py`)

```python
PURPLE = "#BB9AF7"  # tokyo-night primary
CYAN = "#7AA2F7"    # tokyo-night secondary
ACCENT = "#BB9AF7"  # same as primary (kept as its own constant)
DIM = "#6b7280"     # unchanged
```

All consumers reference these constants, so a single edit re-colors:
- banner gradient (`gradient_text`, purple -> periwinkle)
- scan progress spinner/bar (`cli.py` run_scan)
- report borders, headers, and "blacklight-cli" labels (`reporter.py`)
- console mode banner label (`console.py`)

## Verification

- New test: `blacklight.tui.app.BlacklightApp.theme == "tokyo-night"`.
- New test: `theme.PURPLE == "#BB9AF7"`, `theme.CYAN == "#7AA2F7"`,
  `theme.ACCENT == "#BB9AF7"`.
- Existing full suite (249 tests at spec time) stays green — no test pins the
  previous hex values.
- Manual: `blacklight console` renders with the violet/navy palette;
  `blacklight --help` banner and a scan report use the new accents.

## Out of scope (tracked)

- The `[cyan]●` literal in `reporter.py` line 166 is a hardcoded rich color name,
  not a `theme` constant; left as-is per "accents via constants only" scope.
