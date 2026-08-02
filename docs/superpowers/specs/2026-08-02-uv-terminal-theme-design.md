# UV Terminal Theme Revamp — Design

Date: 2026-08-02
Status: Approved (pending spec review)

## Goal

Revamp the blacklight-cli terminal UI with a Metasploit-style "graphical" look:
ASCII banner, animated progress, decorated tables, and a consistent purple/cyan
"UV" color theme. Terminal output only — HTML/Markdown/JSON report exports are
untouched.

## Background: current state

Today the CLI is functional but visually plain:

- `blacklight scan ...` prints a plain `Panel("Summary")`, a host risk table,
  a findings table, and a notes panel — all default rich styling.
- `blacklight web ...` prints the same layout with a web summary.
- `blacklight version` prints a single line.
- The only "motion" is a default spinner + bar in `run_scan`'s `Progress`.
- No logo, banner, or brand identity; no consistent accent color.

This spec introduces a brand: a **UV (purple/cyan) identity** built from the
name *blacklight* (ultraviolet light revealing hidden findings — a fitting
metaphor for a vulnerability scanner).

## User decisions (from brainstorming)

1. Full revamp: banner + animations + decorated output everywhere.
2. Banner appears on **every subcommand invocation**, including
   subcommand-level `--help` (e.g. `blacklight scan --help`). The
   top-level `blacklight --help` and bare `blacklight` invocations do not
   print the banner (click renders group help before the callback runs —
   verified empirically; this relaxation was agreed with the user on
   2026-08-02).
3. Theme: purple/cyan UV — `PURPLE #8b5cf6`, `CYAN #22d3ee`,
   accent `ACCENT #f0abfc`, dim `DIM #6b7280`.
4. Banner art: block-letter `BLACKLIGHT` wordmark with a small lens/beam
   emblem above it (drawn by hand, not a figlet font).
5. Severity colors stay **semantic** (critical red, high orange, medium
   yellow, low white, unknown dim) — they are meaningful, not decorative.
6. Terminal output only; HTML/Markdown/JSON reports are not themed.
7. No new dependencies (rich is already a dependency).

## Architecture

### Component map

| Component | Change | Responsibility |
|---|---|---|
| `blacklight/theme.py` | **new** | Banner art, gradient rendering, color constants, severity styles, risk gauge, banner printer |
| `blacklight/cli.py` | modified | Print banner in app callback; restyle progress bar |
| `blacklight/reporter.py` | modified | Consume theme constants for panels/tables; gauge in risk table; footer line |
| `tests/test_theme.py` | **new** | Unit tests for theme helpers |
| `tests/test_reporter.py` | modified | Add restyle smoke assertions |
| everything else | untouched | scanner, cve_matcher, enrichment, scoring, web engine, guardrails, paths, export_report, templates |

### Principles

- **Single source of truth:** all colors and art live in `theme.py`; no
  color literals scattered in `cli.py`/`reporter.py`.
- **Stable public API:** `render_terminal`, `findings_table`,
  `web_findings_table`, `host_risk_table`, `export_report`, `run_scan`, and
  the typer commands keep their exact signatures and text content so the
  existing test suite passes unchanged.
- **Theme-aware, terminal-only:** styling applies to rich console output
  only. Rich auto-disables color when stdout is not a TTY, so
  `blacklight scan > report.txt` still works in pipes and CI.

## Theme module (`blacklight/theme.py`) — detailed

### Constants

```python
PURPLE = "#8b5cf6"   # violet-500
CYAN   = "#22d3ee"   # cyan-400
ACCENT = "#f0abfc"   # fuchsia-300, used sparingly for highlights
DIM    = "#6b7280"   # gray-500, for muted labels
```

### Banner art

The banner is ~66 characters wide, stored as a multi-line string with no
trailing whitespace on lines, drawn by hand:

```
        ██    ██             ██████    ██████
        ██  ██  ██           ██    ██  ██   ██   <- emblem
        ██  ██  ██ ...       ... (lens/beam motif, final art chosen in impl)
```

- Art is hand-tuned during implementation to exactly 66 columns.
- Implemented as one plain string `BANNER`; no external font files.
- The emblem (top lines) evokes a lens/blacklight beam; the wordmark is
  `BLACKLIGHT` in block letters.
- `BANNER` is a module-level constant with no color markup — color is applied
  by the renderer, keeping art and styling separate.

### Functions

```python
def gradient_text(text: str) -> rich.text.Text:
    """Return the banner text with a purple→cyan horizontal gradient.

    Each visible character gets a color interpolated from PURPLE (left)
    to CYAN (right) across the banner's full width. Blank lines in the
    art produce empty Text spans so line heights are preserved."""

def print_banner(console: rich.console.Console) -> None:
    """Print the gradient banner. Skipped silently when
    console.width < 70 (prevents wrapping in narrow/CI terminals).
    Nothing is printed at all when skipped."""

def risk_gauge(score: float) -> str:
    """Return a 10-segment meter plus the numeric score.

    >>> risk_gauge(72.4)
    '[orange1]███████░░░[/] 72.4'
    Filled segments = round(score / 10); band color: <30 green,
    <60 yellow, <80 orange, else red. Score clamped to [0, 100],
    formatted to one decimal place."""

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "white",
    "unknown": "dim",
}
# moved verbatim from reporter.py; reporter imports it from theme
```

## CLI changes (`blacklight/cli.py`) — detailed

### Banner on every subcommand invocation

The `_noop` callback (which runs before every subcommand, and also before
typer renders subcommand-level `--help`) becomes:

```python
@app.callback()
def _show_banner() -> None:
    theme.print_banner(console)
```

This means: `blacklight scan ...`, `blacklight web ...`,
`blacklight version`, and their `--help` all print the banner first.
Top-level `blacklight --help` and bare `blacklight` do NOT print it —
click handles group-level help during argument parsing, before the
callback runs (verified empirically with click 8.4.2).

### Progress bar

`run_scan`'s `Progress` is restyled while keeping its structure:

- Spinner: a custom purple-themed spinner string from rich's spinner list
  (e.g. `"aesthetic"`), rendered in `ACCENT` via `Progress(spinner_style=...)`.
- Bar: `bar_width=None` (full width), `bar_style=PURPLE`,
  `complete_style=CYAN`, `finished_style=PURPLE`.
- Phase descriptions (`Scanning hosts with nmap...`, etc.) remain unchanged
  text, styled with a `TextColumn("[cyan]{task.description}")` prefix and the
  word "phase" colored — exact format decided in implementation.
- Behavior in non-TTY contexts is unchanged (rich already degrades the
  progress to a static display).

### version command

Output remains exactly:

```
blacklight-cli 0.1.0
```

(banner already printed by the callback; `tests/test_cli.py::test_version_command`
asserts the substring `blacklight-cli 0.1.0` and must keep passing).

### Guardrails flow

Banner prints before guardrail checks and before any `typer.confirm` prompt —
no change to the confirm logic itself.

## Reporter changes (`blacklight/reporter.py`) — detailed

All changes are presentational; **no text strings are removed or reworded**.
The tests assert substrings like `Web risk score: 11.0`, `Checks run: 18`,
`web report`, `Summary`, `CVE-2024-12345`, `critica` — all must remain.

### Summary panel

```python
Panel(content, title="Summary", border_style=PURPLE, title_align="center")
```
- Content: same lines as today, but the `[bold]blacklight-cli[/] v...` header
  line is rendered in cyan; the rest keeps current formatting.
- Web variant (`web report` line) styled the same way.

### Tables

For `findings_table`, `web_findings_table`, and the host risk score table:

- `Table(..., border_style=CYAN, header_style=f"bold {PURPLE}", expand=True)`
- Title text unchanged (e.g. `Findings`, `Web findings`, `Host risk scores`).
- Severity column cells keep `SEVERITY_STYLE` (imported now from `theme`).
- KEV badge stays `[red]KEV[/red]`.

### Host risk score column

`score_table.add_row(..., theme.risk_gauge(row["score"]), ...)` — replacing
the plain `f"{row['score']:.1f}"` cell.

### Notes/footer panel

```python
Panel(notes_text, title="Notes", border_style=PURPLE)
```
- Existing notes text unchanged.
- Appended final line, styled with UV accents:
  `"[cyan]●[/] Scan complete — report written by [bold magenta]blacklight-cli[/]"`
  (wording finalized in implementation; must not collide with asserted substrings).

### render_terminal signature

`render_terminal(findings, meta, console=None, web_findings=None, web_meta=None)`
— unchanged.

## Example output (illustrative, final art TBD in implementation)

```
   ██   ╔══╗   ██             (emblem + wordmark in purple→cyan gradient)
   ██   ╚══╝   ██     B L A C K L I G H T

 ┌─ Summary ────────────────────────────────────────────┐
 │ blacklight-cli v0.1.0 - scan report                  │
 │ Targets: 192.168.1.0/24 | Hosts scanned: 5 | ...     │
 └──────────────────────────────────────────────────────┘
┌ Host risk scores ─────────────────────────┐
│ Host           Risk score (0-100)  Findings│
│ 192.168.1.10   [████████░░] 78.1     3     │
└─────────────────────────────────────────────┘
 ... findings table (cyan borders, purple headers) ...
 ┌─ Notes ──────────────────────────────────────────────┐
 │ Risk score: severity-weighted base (capped at 60)... │
 │ ● Scan complete                                     │
 └──────────────────────────────────────────────────────┘
```

(Exact table widths and box characters are decided by rich at render time;
this sketch communicates layout, not pixel-perfection.)

## Edge cases & error handling

| Case | Behavior |
|---|---|
| Console width < 70 | `print_banner` prints nothing (no exception, no partial banner) |
| Non-TTY stdout (pipe/CI) | Rich strips colors; banner still prints; progress degrades gracefully |
| `--help` invocation (subcommand) | Banner prints above subcommand help text (callback runs first); top-level group `--help` has no banner (click renders it before the callback) |
| Score outside [0,100] | `risk_gauge` clamps before formatting |
| Web scan with zero findings | Same restyled panels; no tables printed (current behavior preserved) |
| Terminal without color support | Rich falls back to no-color styles; nothing crashes |

## Testing plan

### Existing tests (must stay green)

`python -m pytest` — all of `tests/`. Key substrings relied upon:
- `blacklight-cli 0.1.0` (test_cli.py::test_version_command)
- `Web risk score: 11.0`, `Checks run: 18`, `web report`,
  `Possible SQL injection` (test_reporter.py)
- `Summary`, `CVE-2024-12345`, `critica` (test_reporter.py)

### New tests (`tests/test_theme.py`)

1. `test_banner_all_lines_same_width` — every line of `BANNER` is the same
   width and ≤ 70 chars; no trailing whitespace.
2. `test_gradient_text_returns_colored` — `gradient_text` output contains
   styled spans (`Text` segments have style set) and preserves line count.
3. `test_print_banner_skips_narrow_console` — a `Console(width=60)` records
   empty output; `Console(width=160)` records non-empty output.
4. `test_print_banner_styled` — exported text of a width-160 console contains
   `BLACKLIGHT` (or the wordmark).
5. `test_risk_gauge_boundaries` — scores 0, 29.9, 30, 59.9, 60, 79.9, 80, 100
   map to the correct fill count and band color; clamping for -5 and 150.
6. `test_risk_gauge_format` — output ends with one-decimal score, e.g.
   `72.4`.

### Reporter smoke tests (added to `tests/test_reporter.py`)

1. `test_render_terminal_styled` — after restyle, `render_terminal` output
   still contains `Summary`, `Host risk scores`, `Scan complete`.
2. `test_risk_gauge_in_host_table` — host risk table cell contains `██` fill
   characters.

### Verification commands

```
python -m pytest
```

## Out of scope

- HTML/Markdown/JSON report theming.
- Interactive/TUI mode, full-screen layouts.
- New dependencies (no pyfiglet, no textual).
- Changing command names, flags, guardrails, or report content.
- Banner configurability (no `--no-banner` flag; no theme switching).
