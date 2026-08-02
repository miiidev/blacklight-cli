# UV Terminal Theme Revamp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give blacklight-cli a Metasploit-style terminal look — ASCII banner, UV purple/cyan theme, animated progress, decorated tables — without breaking any existing behavior.

**Architecture:** New `blacklight/theme.py` is the single source of visual identity (banner art, colors, severity styles, risk gauge). `cli.py` prints the banner from its callback and restyles the progress bar; `reporter.py` consumes theme constants for panels/tables. All public function signatures and all printed text strings stay unchanged, so the existing test suite passes unmodified.

**Tech Stack:** Python 3.11+, typer, rich (both already installed), pytest.

## Global Constraints

- No new dependencies.
- Terminal output only; HTML/Markdown/JSON exports untouched.
- Severity colors stay semantic: critical `bold red`, high `dark_orange`, medium `yellow`, low `white`, unknown `dim`.
- Theme colors: `PURPLE = "#8b5cf6"`, `CYAN = "#22d3ee"`, `ACCENT = "#f0abfc"`, `DIM = "#6b7280"`.
- Every printed text string currently asserted by tests stays verbatim: `blacklight-cli 0.1.0`, `Web risk score: 11.0`, `Checks run: 18`, `web report`, `Summary`, `CVE-2024-12345`, `critica`.
- Banner prints on every invocation including `--help` (via the typer callback).
- Banner is skipped silently when `console.width < 70`.
- Commit after every task with the message shown in the task.

---

### Task 1: Theme module — banner, colors, risk gauge

**Files:**
- Create: `blacklight/theme.py`
- Test: `tests/test_theme.py` (new file)

**Interfaces:**
- Consumes: nothing (rich only).
- Produces (used by Tasks 2–3):
  - `theme.BANNER: str`
  - `theme.PURPLE`, `theme.CYAN`, `theme.ACCENT`, `theme.DIM: str`
  - `theme.SEVERITY_STYLE: dict[str, str]`
  - `theme.gradient_text(text: str) -> rich.text.Text`
  - `theme.print_banner(console: rich.console.Console) -> None`
  - `theme.risk_gauge(score: float) -> str`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_theme.py`:

```python
from rich.console import Console

from blacklight import theme


def test_banner_lines_are_clean_and_narrow():
    for line in theme.BANNER.splitlines():
        assert len(line) <= 70
        assert line == line.rstrip()


def test_banner_has_wordmark_and_tagline():
    assert len(theme.BANNER.splitlines()) >= 9
    assert "scan · find · illuminate" in theme.BANNER


def test_gradient_text_preserves_content_and_colors():
    text = theme.gradient_text(theme.BANNER)
    assert text.plain == theme.BANNER
    styled = [span for span in text.spans if span.style]
    assert styled


def test_print_banner_skips_narrow_console():
    console = Console(record=True, width=60)
    theme.print_banner(console)
    assert console.export_text() == ""


def test_print_banner_prints_on_wide_console():
    console = Console(record=True, width=160)
    theme.print_banner(console)
    assert "scan · find · illuminate" in console.export_text()


def test_risk_gauge_band_colors():
    assert "green" in theme.risk_gauge(0.0)
    assert "green" in theme.risk_gauge(29.9)
    assert "yellow" in theme.risk_gauge(30.0)
    assert "yellow" in theme.risk_gauge(59.9)
    assert "dark_orange" in theme.risk_gauge(60.0)
    assert "dark_orange" in theme.risk_gauge(79.9)
    assert "red" in theme.risk_gauge(80.0)
    assert "red" in theme.risk_gauge(100.0)


def test_risk_gauge_fill_counts():
    assert theme.risk_gauge(0.0) == "[green]░░░░░░░░░░[/] 0.0"
    assert theme.risk_gauge(25.0).startswith("[green]███")
    assert theme.risk_gauge(72.4).startswith("[dark_orange]███████")
    assert theme.risk_gauge(100.0) == "[red]██████████[/] 100.0"


def test_risk_gauge_clamps():
    assert theme.risk_gauge(-5) == "[green]░░░░░░░░░░[/] 0.0"
    assert theme.risk_gauge(150) == "[red]██████████[/] 100.0"
    assert theme.risk_gauge(72.4).endswith("72.4")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_theme.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'blacklight.theme'`

- [ ] **Step 3: Write the implementation**

Create `blacklight/theme.py`:

```python
"""Visual identity for blacklight-cli: banner art, colors, and gauges."""

from rich.console import Console
from rich.text import Text

PURPLE = "#8b5cf6"
CYAN = "#22d3ee"
ACCENT = "#f0abfc"
DIM = "#6b7280"

BANNER = """\
         ▄▄▄▄▄▄▄▄▄▄
        ▐████████████▌
        ▐█ ▄▄█▀▀█▄▄ █▌
         ▀▀▀▀▀▀▀▀▀▀▀▀
███ █    █   ██ █ █ █   ███  ██ █ █ ███
█ █ █  █ █ █   █ █ █ █    █ █   █ █ █ █  █
███ █  ███ █   ██  █    █  █ ██ ███  █
█ █ █  █ █ █   █ █ █ █    █  █ █ █ █  █
███ ███ █ █  ██ █ █ ███ ███  ██ █ █  █
       scan · find · illuminate"""

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "white",
    "unknown": "dim",
}


def _lerp_hex(start: str, end: str, t: float) -> str:
    """Interpolate two hex colors; t in [0, 1]."""

    def channels(color: str) -> tuple[int, int, int]:
        raw = color.lstrip("#")
        return tuple(int(raw[i : i + 2], 16) for i in (0, 2, 4))

    a, b = channels(start), channels(end)
    rgb = tuple(round(x + (y - x) * t) for x, y in zip(a, b))
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def gradient_text(text: str) -> Text:
    """Render text with a purple-to-cyan gradient across its width."""
    lines = text.splitlines()
    max_width = max(len(line) for line in lines)
    out = Text()
    for i, line in enumerate(lines):
        for col, ch in enumerate(line):
            if ch == " ":
                out.append(" ")
            else:
                t = col / max(max_width - 1, 1)
                out.append(ch, style=_lerp_hex(PURPLE, CYAN, t))
        if i < len(lines) - 1:
            out.append("\n")
    return out


def print_banner(console: Console) -> None:
    """Print the gradient banner; skip silently when the console is narrow."""
    if console.width < 70:
        return
    console.print(gradient_text(BANNER))


def risk_gauge(score: float) -> str:
    """Ten-segment colored meter with the numeric score.

    Band colors: <30 green, <60 yellow, <80 dark_orange, else red.
    Score is clamped to [0, 100]; fill count rounds half-up.
    """
    clamped = max(0.0, min(100.0, score))
    filled = int(clamped / 10 + 0.5)
    if clamped < 30:
        color = "green"
    elif clamped < 60:
        color = "yellow"
    elif clamped < 80:
        color = "dark_orange"
    else:
        color = "red"
    bar = "█" * filled + "░" * (10 - filled)
    return f"[{color}]{bar}[/] {clamped:.1f}"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_theme.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add blacklight/theme.py tests/test_theme.py
git commit -m "feat: add UV theme module with banner, gradient, risk gauge"
```

---

### Task 2: Banner on every invocation + restyled progress bar

**Files:**
- Modify: `blacklight/cli.py:1-30` (imports, callback) and `blacklight/cli.py:157-174` (progress)
- Test: `tests/test_cli.py` (add one test)

**Interfaces:**
- Consumes: `theme.print_banner`, `theme.ACCENT`, `theme.CYAN`, `theme.PURPLE` (from Task 1)
- Produces: nothing new for later tasks; keeps `app`, `run_scan`, and the `version` command text unchanged.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli.py`:

```python
def test_banner_printed_on_invocation():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "scan · find · illuminate" in result.output
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py::test_banner_printed_on_invocation -v`
Expected: FAIL — `assert 'scan · find · illuminate' in result.output`

- [ ] **Step 3: Implement banner callback and progress restyle**

In `blacklight/cli.py`:

1. Add `from blacklight import theme` to the imports block (after the existing `from blacklight import __version__, paths` line).
2. Replace the `_noop` callback:

```python
@app.callback()
def _show_banner() -> None:
    """Show the brand banner on every invocation, including --help."""
    theme.print_banner(console)
```

3. Replace the `Progress(...)` block inside `run_scan` (keep the surrounding code identical):

```python
    with Progress(
        SpinnerColumn(spinner_name="aesthetic", style=theme.ACCENT),
        TextColumn("[cyan]{task.description}"),
        BarColumn(
            bar_width=None,
            complete_style=theme.CYAN,
            finished_style=theme.PURPLE,
        ),
        console=console,
    ) as progress:
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS (all tests including `test_version_command`, which still finds `blacklight-cli 0.1.0`)

- [ ] **Step 5: Commit**

```bash
git add blacklight/cli.py tests/test_cli.py
git commit -m "feat: print UV banner on every invocation, style progress bar"
```

---

### Task 3: Reporter theming — panels, tables, gauge, footer

**Files:**
- Modify: `blacklight/reporter.py`
- Test: `tests/test_reporter.py` (add two tests)

**Interfaces:**
- Consumes: `theme.PURPLE`, `theme.CYAN`, `theme.ACCENT`, `theme.SEVERITY_STYLE`, `theme.risk_gauge` (from Task 1)
- Produces: unchanged public API — `render_terminal`, `findings_table`, `web_findings_table`, `host_risk_table`, `export_report`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_reporter.py`:

```python
def test_render_terminal_has_footer():
    console = Console(record=True, width=160)
    render_terminal([_finding()], META, console=console)
    assert "Scan complete" in console.export_text()


def test_render_terminal_risk_gauge_in_score_table():
    console = Console(record=True, width=160)
    render_terminal([_finding()], META, console=console)
    text = console.export_text()
    assert "░" in text
    assert "█" in text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_reporter.py::test_render_terminal_has_footer tests/test_reporter.py::test_render_terminal_risk_gauge_in_score_table -v`
Expected: FAIL on both (no footer, no gauge characters)

- [ ] **Step 3: Implement reporter theming**

In `blacklight/reporter.py`:

1. Replace the import line `from blacklight.scoring import host_risk_score, web_risk_score` stays; add after `from blacklight import __version__`:

```python
from blacklight.theme import ACCENT, CYAN, PURPLE, SEVERITY_STYLE, risk_gauge
```

2. Delete the local `SEVERITY_STYLE = {...}` dict (lines 17–23) — it is now imported.

3. `findings_table` — change the table constructor:

```python
    table = Table(
        title="Findings",
        expand=True,
        border_style=CYAN,
        header_style=f"bold {PURPLE}",
    )
```

4. `web_findings_table` — change the table constructor:

```python
    table = Table(
        title="Web findings",
        expand=True,
        border_style=CYAN,
        header_style=f"bold {PURPLE}",
    )
```

5. `_web_summary_text` — keep every word identical; style the header cyan:

```python
def _web_summary_text(web_findings: list[WebFinding], web_meta: dict) -> str:
    return (
        f"[bold {ACCENT}]blacklight-cli[/] v{__version__} - web report\n"
        f"URL: [bold]{web_meta['url']}[/] ({web_meta['resolved_ip']}) | "
        f"Checks run: {web_meta['checks_run']} | Checks errored: {web_meta['checks_errored']} | "
        f"Web findings: {len(web_findings)} | Web risk score: {web_risk_score(web_findings):.1f}"
    )
```

6. In `render_terminal`, replace the two `Panel(...)` calls' styling and the score table:

- Network summary panel:

```python
        console.print(
            Panel(
                f"[bold {ACCENT}]blacklight-cli[/] v{__version__} - scan report\n"
                f"Targets: [bold]{meta.get('targets', '')}[/] | Hosts scanned: {meta.get('hosts_scanned', 0)} | "
                f"Services found: {meta.get('services_found', 0)} | Findings: {meta.get('findings_count', 0)}",
                title="Summary",
                border_style=PURPLE,
                title_align="center",
            )
        )
```

- Web summary panel call becomes:

```python
        console.print(
            Panel(
                _web_summary_text(web_findings, web_meta),
                title="Summary",
                border_style=PURPLE,
                title_align="center",
            )
        )
```

- Host risk score table:

```python
        score_table = Table(
            title="Host risk scores",
            expand=True,
            border_style=CYAN,
            header_style=f"bold {PURPLE}",
        )
        score_table.add_column("Host")
        score_table.add_column("Risk score (0-100)")
        score_table.add_column("Findings")
        for row in hosts:
            score_table.add_row(row["host"], risk_gauge(row["score"]), str(row["findings"]))
```

- Notes panel (keep the two existing text lines verbatim, add a footer line):

```python
    console.print(
        Panel(
            "Risk score: severity-weighted base (capped at 60) + 10 per KEV finding "
            "(capped at 20) + max EPSS x 10, capped at 100.\n"
            "For use only on systems you own or are authorized to test.\n"
            f"[cyan]●[/] [bold {ACCENT}]Scan complete[/] — report written by blacklight-cli",
            title="Notes",
            border_style=PURPLE,
        )
    )
```

- [ ] **Step 4: Run reporter tests to verify they pass**

Run: `python -m pytest tests/test_reporter.py -v`
Expected: PASS (all 9 tests, including the two new ones and the existing
string assertions)

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add blacklight/reporter.py tests/test_reporter.py
git commit -m "feat: theme reporter output with UV panels, gauges, footer"
```

---

### Task 4: Final verification and spec alignment

**Files:**
- Modify: `docs/superpowers/specs/2026-08-02-uv-terminal-theme-design.md` (test wording)
- No code changes.

- [ ] **Step 1: Align the spec's banner test wording**

In the spec file, replace the banner width test line:

```
1. `test_banner_all_lines_same_width` — every line of `BANNER` is the same
   width and ≤ 70 chars; no trailing whitespace.
```

with:

```
1. `test_banner_lines_are_clean_and_narrow` — every line of `BANNER` is
   ≤ 70 chars; no trailing whitespace; at least 9 lines; contains the
   `scan · find · illuminate` tagline.
```

(Why: the banner mixes a centered emblem with a wider wordmark, so lines
are not all the same width by design.)

- [ ] **Step 2: Manual smoke test**

Run:
```bash
blacklight version
blacklight --help
blacklight scan --help
```
Expected: the gradient banner prints before every command's output; help text follows the banner; no tracebacks. (If the block-glyph banner looks garbled in a legacy `cmd.exe`, that is cosmetic only — behavior and tests are unaffected.)

- [ ] **Step 3: Run full suite once more**

Run: `python -m pytest -q`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-08-02-uv-terminal-theme-design.md
git commit -m "docs: align banner test wording in UV theme spec"
```
