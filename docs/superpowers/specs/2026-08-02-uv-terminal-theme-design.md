# UV Terminal Theme Revamp — Design

Date: 2026-08-02
Status: Approved (pending spec review)

## Goal

Revamp the blacklight-cli terminal UI with a Metasploit-style "graphical" look: ASCII banner, animated progress, decorated tables, and a consistent purple/cyan "UV" color theme. Terminal output only — HTML/Markdown/JSON report exports are untouched.

## User decisions

- Full revamp: banner + animations + decorated output everywhere.
- Banner appears on **every invocation**, including `--help`.
- Theme: purple/cyan UV (`#8b5cf6` / `#22d3ee`), accent pink `#f0abfc`.
- Banner art: block-letter `BLACKLIGHT` wordmark with a small lens/beam emblem above it.
- Severity colors stay **semantic** (critical red, high orange, medium yellow, low white, unknown dim).
- Terminal only; exported reports are not themed.

## Architecture

- **New module `blacklight/theme.py`** — single source of visual identity:
  banner art, color constants, severity styles, risk gauge, banner printer.
  No new dependencies (rich is already a dependency).
- **`blacklight/cli.py`** — banner printed in the app callback (runs on every
  invocation, including `--help`), progress bar restyled.
- **`blacklight/reporter.py`** — tables/panels consume theme constants.
  All public function signatures stay unchanged.
- Not touched: `reporter.export_report`, HTML/MD/JSON templates, scanner,
  cve_matcher, enrichment, scoring, web engine, guardrails, paths.

## Theme module (`theme.py`)

- `BANNER: str` — hand-crafted ASCII art, ~66 characters wide: emblem above
  the `BLACKLIGHT` wordmark.
- `gradient_text(text) -> Text` — applies a purple→cyan gradient across the
  banner using rich styling.
- `print_banner(console)` — prints the banner; skipped silently if
  `console.width < 70` (prevents wrapping in narrow/CI terminals).
- Color constants: `PURPLE = "#8b5cf6"`, `CYAN = "#22d3ee"`,
  `ACCENT = "#f0abfc"`, `DIM = "#6b7280"`.
- `SEVERITY_STYLE` — moved here from `reporter.py` (same values).
- `risk_gauge(score: float) -> str` — colored meter of the form
  `[███████░░░] 72.4`; 10 segments filled proportionally, band colors:
  `<30` green, `<60` yellow, `<80` orange, else red.

## CLI changes (`cli.py`)

- The `_noop` callback calls `theme.print_banner(console)` before anything else.
- Progress bar in `run_scan`: custom spinner, purple bar, cyan phase
  descriptions. API usage stays compatible with existing code.
- `version` command output keeps the exact `blacklight-cli 0.1.0` line
  (test asserts this substring).

## Reporter changes (`reporter.py`)

- Summary panel: UV border color, title in cyan/purple.
- Tables (`findings_table`, `web_findings_table`, host risk table):
  `border_style=CYAN`, bold purple headers. Severity text colors unchanged.
- Host risk score column renders `risk_gauge(score)`.
- Notes/footer panel: UV border; append a "scan complete" footer line with
  UV accents.
- All existing text strings stay verbatim (e.g. `Web risk score: 11.0`,
  `Checks run: 18`, `web report` — tests assert these substrings).

## Testing

- Full existing test suite must stay green (assertions are substring-based;
  the added banner does not remove any asserted text).
- New tests:
  - `theme` — banner renders and all lines are equal width (<= 70 chars);
    gradient produces colored output; gauge fills/band colors correct for
    boundary scores (0, 29.9, 30, 59.9, 60, 79.9, 80, 100).
  - `reporter` — `render_terminal` still contains key strings after restyle.
- Run `python -m pytest` locally to verify.

## Out of scope

- HTML/Markdown/JSON report theming.
- Interactive/TUI mode, full-screen layouts.
- New dependencies.
- pyfiglet dynamic fonts.
