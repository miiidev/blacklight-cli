# Interactive Console Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an msfconsole-style interactive session (`use` / `set` / `run` / `back` / `exit`) that reuses the existing scan/web pipelines and guardrails, entered via bare `blacklight` or `blacklight console`.

**Architecture:** Extract the orchestration embedded in the `scan()`/`web()` CLI commands into shared `execute_scan`/`execute_web` functions with an injectable `confirm` callback; both CLI commands and the new console call them. The console is two layers: a pure, prompt_toolkit-free `CommandRunner` (fully unit-testable) and a `ConsoleApp` REPL loop (prompt_toolkit when interactive, plain `input()`-style loop when piped).

**Tech Stack:** Python 3.11+, typer, rich, prompt_toolkit (new required dep, lazily imported).

## Global Constraints

- Version `0.2.0` in `pyproject.toml` and `blacklight/__init__.py::__version__`.
- New required dependency: `prompt_toolkit>=3` in `pyproject.toml` `[project] dependencies`. It must be imported lazily (inside the interactive path only) so `scan`/`web`/`version` never load it.
- Command set is exactly: `help`, `modules`, `use <name>`, `show options`, `set <OPT> <value>`, `unset <OPT>`, `run`, `back`, `exit`/`quit`. Unknown command → error hint, loop continues.
- Module options exactly mirror the CLI flags (spec table): scan = TARGET, PORTS, OUTPUT, FORMAT, NO_CACHE, TIMEOUT, PERMISSION; web = TARGET, TIMEOUT, NO_CACHE, OUTPUT, FORMAT, PERMISSION. Defaults: TARGET="" PORTS="1-1024" OUTPUT="" FORMAT="html" NO_CACHE="false" TIMEOUT="30" PERMISSION="false".
- `permission_granted` semantics (unchanged from today's CLI): `False` → public targets blocked outright, no prompt; `True` → public targets move to needs-confirmation and the injected `confirm(message)` callback decides.
- `scan`/`web` CLI commands keep their exact signatures and flags; existing 149 tests stay green.
- Console exits with code 0; errors print `[red]` lines and the loop continues; Ctrl-D (EOF) ends the loop.
- Run tests with `python -m pytest` (Windows dev machine). All project files are UTF-8; do not add non-ASCII beyond the existing block glyphs in `theme.py`.

---

### Task 1: Extract `execute_scan` / `execute_web` shared orchestration

**Files:**
- Modify: `blacklight/cli.py` (add import; replace bodies of `scan()` and `web()` with thin wrappers; add two new module-level functions)
- Test: `tests/test_cli.py`
- Modify: `docs/superpowers/specs/2026-08-03-console-mode-design.md` (one testing-section wording fix)

**Interfaces:**
- Consumes: existing `guardrails.verify_targets`, `guardrails.normalize_web_url`, `guardrails.verify_web_target`, `scanner.find_nmap`, `run_scan` (module-level in cli.py), `run_web_scan`, `_log_scan`, `_log_web_scan`, `render_terminal`, `export_report`, module-level `console`.
- Produces (used by Task 2/3 and by the thin wrappers):

```python
def execute_scan(targets: list[str], *, ports: str, timeout: int, no_cache: bool,
                 output: Path | None, fmt: str,
                 permission_granted: bool, confirm: Callable[[str], bool]) -> int: ...

def execute_web(url: str, *, timeout: int, no_cache: bool,
                output: Path | None, fmt: str,
                permission_granted: bool, confirm: Callable[[str], bool]) -> int: ...
```

Both print exactly the messages today's commands print and return `0` on success, `1` on any failure.

- [ ] **Step 1: Write the failing tests for `execute_scan`**

Append to `tests/test_cli.py`. First add imports at the top of the file:

```python
from types import SimpleNamespace

from blacklight import __version__
from blacklight.cli import app, execute_scan, execute_web, run_scan
```

(`__version__` is imported here but only used in Task 3's version-test update in `tests/test_cli.py` — the same import block is edited again there. `test_version_command` stays as-is (hardcoded 0.1.0) until Task 3.)

Now append these tests:

```python
def never_confirm(message):
    raise AssertionError("confirm must not be called")


def test_execute_scan_blocks_public_target_without_permission(monkeypatch, capsys):
    def fail(*a, **k):
        raise AssertionError("scan pipeline must not run for blocked targets")

    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", fail)
    code = execute_scan(["8.8.8.8"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=False, confirm=never_confirm)
    assert code == 1
    assert "Blocked" in capsys.readouterr().out


def test_execute_scan_aborts_when_confirm_declines(monkeypatch, tmp_path, capsys):
    def fail(*a, **k):
        raise AssertionError("scan pipeline must not run when confirm declines")

    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", fail)
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    calls = []

    def declining(message):
        calls.append(message)
        return False

    code = execute_scan(["8.8.8.8"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=True, confirm=declining)
    assert code == 1
    assert calls
    assert "Aborted" in capsys.readouterr().out
    assert not (tmp_path / "scan.log").exists()


def test_execute_scan_confirm_true_proceeds(monkeypatch, tmp_path, capsys):
    records = [ScanRecord(host="8.8.8.8", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    calls = []
    code = execute_scan(["8.8.8.8"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=True,
                        confirm=lambda m: calls.append(m) or True)
    assert code == 0
    assert calls
    out = capsys.readouterr().out
    assert "scan report" in out
    assert "Hosts scanned: 1" in out


def test_execute_scan_private_target_skips_confirm(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    code = execute_scan(["192.168.1.10"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=False, confirm=never_confirm)
    assert code == 0


def test_execute_scan_exports_report(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    out = tmp_path / "report.json"
    code = execute_scan(["192.168.1.10"], ports="22", timeout=30, no_cache=False,
                        output=out, fmt="json",
                        permission_granted=False, confirm=never_confirm)
    assert code == 0
    assert out.exists()
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `python -m pytest tests/test_cli.py -v`
Expected: `ERROR` collection failures (ImportError: cannot import name 'execute_scan').

- [ ] **Step 3: Extract `execute_scan` from the `scan` command body**

In `blacklight/cli.py`:

1. Add the import after `import sys` (line 5):

```python
from collections.abc import Callable
```

2. Replace the entire body of the `scan()` command (lines 43-103, from `@app.command()` through the closing of the old body) with a thin wrapper. Keep the existing `@app.command()` decorator and the exact parameter list and docstring:

```python
@app.command()
def scan(
    target: list[str] = typer.Argument(..., help="Target host(s) or CIDR(s)."),
    ports: str = typer.Option("1-1024", "--ports", "-p", help="Port range(s) to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Export report to a file."),
    fmt: str = typer.Option("html", "--format", help="Export format: html, markdown, json."),
    i_have_permission: bool = typer.Option(
        False, "--i-have-permission",
        help="Confirm you are authorized to scan these targets.",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the local NVD/EPSS cache."),
    timeout: int = typer.Option(30, "--timeout", help="Per-host nmap scan timeout in seconds."),
) -> None:
    """Scan targets for vulnerable services and report findings."""
    raise typer.Exit(code=execute_scan(
        list(target),
        ports=ports,
        timeout=timeout,
        no_cache=no_cache,
        output=output,
        fmt=fmt,
        permission_granted=i_have_permission,
        confirm=lambda message: typer.confirm(message),
    ))
```

3. Add the `execute_scan` function directly after the `scan()` command (before the `web` command). It contains the old body, with three changes: `confirm` is a parameter instead of `typer.confirm`, every `raise typer.Exit(code=1)` becomes `return 1`, and the success path ends with `return 0`:

```python
def execute_scan(
    targets: list[str], *,
    ports: str, timeout: int, no_cache: bool,
    output: Path | None, fmt: str,
    permission_granted: bool, confirm: Callable[[str], bool],
) -> int:
    """Verify targets under guardrails, run the scan pipeline, log, render,
    and export. Returns the process exit code (0 or 1)."""
    paths.ensure_dirs()
    verdict = guardrails.verify_targets(targets, permission_granted)
    for blocked in verdict.blocked:
        console.print(f"[red]Blocked:[/] {blocked} is not a private address. "
                      "Pass --i-have-permission to allow scanning non-private targets.")
    if verdict.needs_confirmation:
        names = ", ".join(verdict.needs_confirmation)
        if not confirm(f"Target(s) {names} are public. "
                       "Are you authorized to scan them?"):
            console.print("[yellow]Aborted.[/]")
            return 1
    targets = verdict.allowed + verdict.needs_confirmation
    if not targets:
        console.print("[red]No scannable targets.[/]")
        return 1
    if scanner.find_nmap() is None:
        console.print("[red]nmap not found.[/] Install it with one of:\n"
                      "  apt:   sudo apt install nmap\n"
                      "  brew:  brew install nmap\n"
                      "  choco: choco install nmap")
        return 1
    if fmt not in ("html", "markdown", "json"):
        console.print("[red]Invalid format.[/] Choose html, markdown, or json.")
        return 1
    if output is not None and fmt == "html" and output.suffix in (".md", ".json"):
        fmt = "markdown" if output.suffix == ".md" else "json"

    try:
        result = run_scan(targets, ports, timeout, no_cache)
    except (
        requests.RequestException,
        subprocess.TimeoutExpired,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        console.print(f"[red]Scan failed:[/] {exc}")
        return 1
    _log_scan(targets, permission_granted, result["meta"])
    render_terminal(result["findings"], result["meta"])
    if output is not None:
        try:
            export_report(result["findings"], result["meta"], fmt, output)
        except (OSError, ValueError) as exc:
            console.print(f"[red]Report export failed:[/] {exc}")
            return 1
        console.print(f"Report written to [bold]{output}[/]")
    return 0
```

- [ ] **Step 4: Extract `execute_web` from the `web` command body**

Same pattern. Replace the body of `web()` (lines 106-158) with the thin wrapper (keeping decorator, params, docstring):

```python
@app.command()
def web(
    url: str = typer.Argument(..., help="Web target URL (hostname or http(s) URL)."),
    i_have_permission: bool = typer.Option(
        False, "--i-have-permission",
        help="Confirm you are authorized to scan this target.",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the local NVD/EPSS cache."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Export report to a file."),
    fmt: str = typer.Option("html", "--format", help="Export format: html, markdown, json."),
    timeout: int = typer.Option(30, "--timeout", help="HTTP request timeout in seconds."),
) -> None:
    """Scan a web application for misconfigurations and injection flaws."""
    raise typer.Exit(code=execute_web(
        url,
        timeout=timeout,
        no_cache=no_cache,
        output=output,
        fmt=fmt,
        permission_granted=i_have_permission,
        confirm=lambda message: typer.confirm(message),
    ))
```

And add `execute_web` right after it:

```python
def execute_web(
    url: str, *,
    timeout: int, no_cache: bool,
    output: Path | None, fmt: str,
    permission_granted: bool, confirm: Callable[[str], bool],
) -> int:
    """Same shape as execute_scan for web targets."""
    paths.ensure_dirs()
    url = guardrails.normalize_web_url(url)
    verdict = guardrails.verify_web_target(url, permission_granted)
    for blocked in verdict.blocked:
        console.print(f"[red]Blocked:[/] {blocked} must be an http(s) URL for a private "
                      "host, or pass --i-have-permission for public hosts.")
    if verdict.needs_confirmation:
        if not confirm(f"Target {url} is public. Are you authorized to scan it?"):
            console.print("[yellow]Aborted.[/]")
            return 1
    if not (verdict.allowed or verdict.needs_confirmation):
        console.print("[red]No scannable targets.[/]")
        return 1
    if fmt not in ("html", "markdown", "json"):
        console.print("[red]Invalid format.[/] Choose html, markdown, or json.")
        return 1
    if output is not None and fmt == "html" and output.suffix in (".md", ".json"):
        fmt = "markdown" if output.suffix == ".md" else "json"

    try:
        result = run_web_scan(url, timeout, no_cache)
    except (
        requests.RequestException,
        subprocess.TimeoutExpired,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        console.print(f"[red]Web scan failed:[/] {exc}")
        return 1
    _log_web_scan(url, permission_granted, result.meta)
    render_terminal([], {}, web_findings=result.findings, web_meta=result.meta)
    if output is not None:
        try:
            export_report([], {}, fmt, output,
                          web_findings=result.findings, web_meta=result.meta)
        except (OSError, ValueError) as exc:
            console.print(f"[red]Report export failed:[/] {exc}")
            return 1
        console.print(f"Report written to [bold]{output}[/]")
    return 0
```

- [ ] **Step 5: Write the `execute_web` tests and run the full CLI test file**

Append to `tests/test_cli.py`:

```python
WEB_META = {
    "url": "https://example.com",
    "resolved_ip": "1.2.3.4",
    "checks_run": 1,
    "checks_errored": 0,
    "cve_findings": 0,
    "generated": "2026-08-04T00:00:00+00:00",
}


def test_execute_web_blocks_public_without_permission(monkeypatch, capsys):
    def fail(*a, **k):
        raise AssertionError("web pipeline must not run for blocked targets")

    monkeypatch.setattr("blacklight.cli.guardrails.resolve_hostname",
                        lambda h: "1.2.3.4")
    monkeypatch.setattr("blacklight.cli.run_web_scan", fail)
    code = execute_web("https://example.com", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=False, confirm=never_confirm)
    assert code == 1
    assert "Blocked" in capsys.readouterr().out


def test_execute_web_aborts_when_confirm_declines(monkeypatch, tmp_path, capsys):
    def fail(*a, **k):
        raise AssertionError("web pipeline must not run when confirm declines")

    monkeypatch.setattr("blacklight.cli.guardrails.resolve_hostname",
                        lambda h: "1.2.3.4")
    monkeypatch.setattr("blacklight.cli.run_web_scan", fail)
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    calls = []

    def declining(message):
        calls.append(message)
        return False

    code = execute_web("https://example.com", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=True, confirm=declining)
    assert code == 1
    assert calls
    assert "Aborted" in capsys.readouterr().out
    assert not (tmp_path / "scan.log").exists()


def test_execute_web_confirm_true_proceeds(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("blacklight.cli.guardrails.resolve_hostname",
                        lambda h: "1.2.3.4")
    monkeypatch.setattr("blacklight.cli.run_web_scan",
                        lambda *a, **k: SimpleNamespace(findings=[], meta=WEB_META))
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    calls = []
    code = execute_web("https://example.com", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=True,
                       confirm=lambda m: calls.append(m) or True)
    assert code == 0
    assert calls
    assert "Web risk score" in capsys.readouterr().out


def test_execute_web_private_target_skips_confirm(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.cli.run_web_scan",
                        lambda *a, **k: SimpleNamespace(findings=[], meta=WEB_META))
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    code = execute_web("http://127.0.0.1", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=False, confirm=never_confirm)
    assert code == 0


def test_execute_web_exports_report(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("blacklight.cli.run_web_scan",
                        lambda *a, **k: SimpleNamespace(findings=[], meta=WEB_META))
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    out = tmp_path / "web.json"
    code = execute_web("http://127.0.0.1", timeout=30, no_cache=False,
                       output=out, fmt="json",
                       permission_granted=False, confirm=never_confirm)
    assert code == 0
    assert out.exists()
    assert "Report written to" in capsys.readouterr().out
```

Run: `python -m pytest tests/test_cli.py -v`
Expected: all tests pass, including the 6 pre-existing CLI tests (`test_scan_blocks_public_target_without_permission`, `test_scan_prompts_for_public_target_with_permission`, `test_scan_end_to_end_private_target`, `test_scan_exports_json_output`, `test_run_scan_builds_meta`, `test_scan_reports_missing_nmap`, `test_scan_fails_gracefully_on_upstream_error`, `test_version_command`, `test_banner_printed_on_invocation`). Exit-code and message behavior is unchanged because the wrappers raise `typer.Exit(code=<return value>)` exactly where the old code did.

- [ ] **Step 6: Fix the spec's testing bullet and commit**

In `docs/superpowers/specs/2026-08-03-console-mode-design.md`, line 193, replace the bullet fragment `; `permission_granted=True` skips confirm;` with `; private targets never prompt;` so the bullet reads:

```
- `execute_scan`/`execute_web` (in `tests/test_cli.py`): with monkeypatched
  `scanner.scan_hosts` + fake `NvdClient` + `enrichment` (patterns from
  existing tests): blocked public target without permission (no scan call,
  code 1); public + `permission_granted=True` + `confirm->False` aborts;
  `confirm->True` proceeds; private targets never prompt; export path writes
  file when OUTPUT set.
```

Then run the full suite: `python -m pytest` → Expected: 149 existing + 11 new = 160 pass.

Commit:

```bash
git add blacklight/cli.py tests/test_cli.py docs/superpowers/specs/2026-08-03-console-mode-design.md
git commit -m "refactor: extract execute_scan/execute_web with injectable confirm"
```

---

### Task 2: Console core — module model and `CommandRunner`

**Files:**
- Create: `blacklight/console.py`
- Test: `tests/test_console.py` (new)

**Interfaces:**
- Consumes: `execute_scan` / `execute_web` from Task 1 (signatures above).
- Produces (used by Task 3):

```python
@dataclass(frozen=True)
class Option:
    default: str
    help: str

@dataclass
class Module:
    name: str
    description: str
    options: dict[str, Option]

@dataclass
class ConsoleState:
    modules: dict[str, Module]
    active: str | None = None
    values: dict[str, str] = field(default_factory=dict)

SCAN_MODULE: Module
WEB_MODULE: Module

class CommandRunner:
    def __init__(self, *, execute_scan: Callable[..., int],
                 execute_web: Callable[..., int],
                 confirm: Callable[[str], bool]) -> None: ...
    state: ConsoleState
    def execute(self, line: str, out: TextIO) -> bool: ...   # True = exit loop
```

`CommandRunner` must not import prompt_toolkit or typer. All output goes through a fresh `rich.console.Console(file=out)` per call.

- [ ] **Step 1: Write the failing dispatch tests**

Create `tests/test_console.py`:

```python
import io

from blacklight.console import CommandRunner


def make_runner(**overrides):
    kwargs = {
        "execute_scan": lambda *a, **k: 0,
        "execute_web": lambda *a, **k: 0,
        "confirm": lambda m: True,
    }
    kwargs.update(overrides)
    return CommandRunner(**kwargs)


def run_commands(lines, runner=None):
    runner = runner or make_runner()
    out = io.StringIO()
    for line in lines:
        runner.execute(line, out)
    return runner, out.getvalue()


def test_help_lists_all_commands():
    _, out = run_commands(["help"])
    for word in ("help", "modules", "use", "show options", "set", "unset",
                 "run", "back", "exit"):
        assert word in out


def test_modules_lists_scan_and_web():
    _, out = run_commands(["modules"])
    assert "scan" in out
    assert "web" in out


def test_use_selects_module():
    runner, out = run_commands(["use scan"])
    assert runner.state.active == "scan"
    assert "Using module scan" in out


def test_use_unknown_module_errors_and_keeps_state():
    runner, out = run_commands(["use nope"])
    assert runner.state.active is None
    assert "Unknown module" in out


def test_set_stores_value():
    runner, _ = run_commands(["use scan", "set TARGET 192.168.1.10"])
    assert runner.state.values["TARGET"] == "192.168.1.10"


def test_set_unknown_option_errors():
    _, out = run_commands(["use scan", "set NOPE x"])
    assert "Unknown option: NOPE" in out


def test_set_permission_rejects_non_boolean():
    _, out = run_commands(["use scan", "set PERMISSION maybe"])
    assert "PERMISSION expects true or false" in out


def test_set_before_use_hints():
    _, out = run_commands(["set TARGET 192.168.1.10"])
    assert "No module selected" in out


def test_unset_restores_default():
    runner, _ = run_commands(["use scan", "set TARGET 192.168.1.10", "unset TARGET"])
    assert "TARGET" not in runner.state.values


def test_show_options_lists_active_module_options():
    _, out = run_commands(["use web", "show options"])
    assert "TARGET" in out
    assert "PERMISSION" in out
    assert "http(s)" in out


def test_run_requires_module():
    _, out = run_commands(["run"])
    assert "No module selected" in out


def test_run_requires_target():
    _, out = run_commands(["use scan", "run"])
    assert "TARGET not set" in out


def test_run_invokes_execute_scan_with_converted_options():
    captured = {}

    def fake_scan(targets, **kwargs):
        captured["targets"] = targets
        captured.update(kwargs)
        return 0

    runner, out = run_commands(
        ["use scan", "set TARGET 192.168.1.10,192.168.1.20",
         "set PERMISSION true", "run"],
        make_runner(execute_scan=fake_scan),
    )
    assert captured["targets"] == ["192.168.1.10", "192.168.1.20"]
    assert captured["permission_granted"] is True
    assert captured["ports"] == "1-1024"
    assert captured["timeout"] == 30
    assert captured["no_cache"] is False
    assert captured["fmt"] == "html"
    assert captured["output"] is None
    assert "Done" in out


def test_run_invokes_execute_web_with_first_target():
    captured = {}

    def fake_web(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return 0

    runner, _ = run_commands(
        ["use web", "set TARGET http://127.0.0.1", "run"],
        make_runner(execute_web=fake_web),
    )
    assert captured["url"] == "http://127.0.0.1"
    assert captured["permission_granted"] is False


def test_run_forwards_injected_confirm():
    confirm_cb = lambda m: False  # noqa: E731
    captured = {}

    def fake_scan(targets, **kwargs):
        captured.update(kwargs)
        return 0

    run_commands(
        ["use scan", "set TARGET 8.8.8.8", "set PERMISSION true", "run"],
        make_runner(execute_scan=fake_scan, confirm=confirm_cb),
    )
    assert captured["confirm"] is confirm_cb


def test_run_rejects_non_integer_timeout():
    _, out = run_commands(["use scan", "set TIMEOUT abc", "run"])
    assert "TIMEOUT must be an integer" in out


def test_back_clears_active_module():
    runner, out = run_commands(["use scan", "back"])
    assert runner.state.active is None
    runner, out = run_commands(["back"])
    assert "No module selected" in out


def test_exit_and_quit_return_true():
    runner = make_runner()
    assert runner.execute("exit", io.StringIO()) is True
    assert runner.execute("quit", io.StringIO()) is True


def test_unknown_command_hints():
    _, out = run_commands(["frobnicate"])
    assert "Unknown command: frobnicate" in out


def test_empty_and_blank_lines_are_noops():
    runner = make_runner()
    assert runner.execute("", io.StringIO()) is False
    assert runner.execute("   ", io.StringIO()) is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_console.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.console'`.

- [ ] **Step 3: Implement `blacklight/console.py` — model + runner**

Create `blacklight/console.py`:

```python
"""msfconsole-style interactive session for blacklight-cli."""

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TextIO

from rich.console import Console


@dataclass(frozen=True)
class Option:
    default: str
    help: str


@dataclass
class Module:
    name: str
    description: str
    options: dict[str, Option]


SCAN_MODULE = Module(
    name="scan",
    description="nmap service/version scan -> CVE + EPSS + KEV risk report",
    options={
        "TARGET": Option("", "Host(s) or CIDR(s) to scan (comma or space separated)"),
        "PORTS": Option("1-1024", "Port range(s) to scan"),
        "OUTPUT": Option("", "Export report to a file (html/markdown/json)"),
        "FORMAT": Option("html", "Export format: html, markdown, json"),
        "NO_CACHE": Option("false", "Bypass the local NVD/EPSS cache"),
        "TIMEOUT": Option("30", "Per-host nmap scan timeout in seconds"),
        "PERMISSION": Option("false", "Set true if authorized to scan public targets"),
    },
)

WEB_MODULE = Module(
    name="web",
    description="Passive web app misconfig and injection probe",
    options={
        "TARGET": Option("", "Web target URL (hostname or http(s) URL)"),
        "TIMEOUT": Option("30", "HTTP request timeout in seconds"),
        "NO_CACHE": Option("false", "Bypass the local NVD/EPSS cache"),
        "OUTPUT": Option("", "Export report to a file (html/markdown/json)"),
        "FORMAT": Option("html", "Export format: html, markdown, json"),
        "PERMISSION": Option("false", "Set true if authorized to scan public targets"),
    },
)


@dataclass
class ConsoleState:
    modules: dict[str, Module]
    active: str | None = None
    values: dict[str, str] = field(default_factory=dict)


HELP_TEXT = """Commands:
  help                 Show this help
  modules              List available modules
  use <module>         Select a module (scan, web)
  show options         Show the active module's options
  set <OPT> <value>    Set an option (e.g. set TARGET 192.168.1.10)
  unset <OPT>          Reset an option to its default
  run                  Run the active module with current options
  back                 Deselect the active module
  exit | quit          Leave the console
"""


class CommandRunner:
    """Parses and dispatches one console line at a time.

    Pure by design: the scan/web pipelines and the authorization confirm
    are injected callables, so this class never touches prompt_toolkit,
    typer, or the network.
    """

    def __init__(
        self,
        *,
        execute_scan: Callable[..., int],
        execute_web: Callable[..., int],
        confirm: Callable[[str], bool],
    ) -> None:
        self._execute_scan = execute_scan
        self._execute_web = execute_web
        self._confirm = confirm
        self.state = ConsoleState(modules={"scan": SCAN_MODULE, "web": WEB_MODULE})

    # -- helpers --------------------------------------------------------

    def _active(self) -> Module | None:
        if self.state.active is None:
            return None
        return self.state.modules[self.state.active]

    def _current_value(self, name: str) -> str:
        if name in self.state.values:
            return self.state.values[name]
        return self._active().options[name].default  # type: ignore[union-attr]

    # -- dispatch -------------------------------------------------------

    def execute(self, line: str, out: TextIO = sys.stdout) -> bool:
        """Handle one input line. Returns True when the loop should exit."""
        line = line.strip()
        if not line:
            return False
        parts = line.split(None, 2)
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        console = Console(file=out, highlight=False)

        if cmd in ("exit", "quit"):
            return True
        if cmd == "help":
            out.write(HELP_TEXT)
        elif cmd == "modules":
            for name, module in self.state.modules.items():
                out.write(f"{name:<8} {module.description}\n")
        elif cmd == "use":
            self._use(args, console)
        elif cmd == "show":
            self._show(args, console)
        elif cmd == "set":
            self._set(args, console)
        elif cmd == "unset":
            self._unset(args, console)
        elif cmd == "run":
            self._run(args, console)
        elif cmd == "back":
            if self.state.active is None:
                console.print("[yellow]No module selected.[/]")
            else:
                self.state.active = None
        else:
            console.print(f"[red]Unknown command: {cmd}[/] Type 'help'.")
        return False

    def _use(self, args: list[str], console: Console) -> None:
        if len(args) != 1:
            console.print("[red]Usage: use <module>[/]")
            return
        name = args[0]
        if name not in self.state.modules:
            console.print(f"[red]Unknown module: {name}[/] "
                          f"Available: {', '.join(self.state.modules)}")
            return
        self.state.active = name
        console.print(f"Using module [bold]{name}[/]")

    def _show(self, args: list[str], console: Console) -> None:
        if args != ["options"]:
            console.print("[red]Usage: show options[/]")
            return
        module = self._active()
        if module is None:
            console.print("[red]No module selected. Use 'use <module>' first.[/]")
            return
        console.print(f"Module: [bold]{module.name}[/] - {module.description}")
        console.print(f"{'OPTION':<10} {'CURRENT':<16} {'DEFAULT':<16} DESCRIPTION")
        for name, option in module.options.items():
            console.print(f"{name:<10} {self._current_value(name):<16} "
                          f"{option.default:<16} {option.help}")

    def _set(self, args: list[str], console: Console) -> None:
        module = self._active()
        if module is None:
            console.print("[red]No module selected. Use 'use <module>' first.[/]")
            return
        if len(args) != 2:
            console.print("[red]Usage: set <OPTION> <value>[/]")
            return
        name, value = args[0].upper(), args[1]
        if name not in module.options:
            console.print(f"[red]Unknown option: {name}[/] "
                          f"Valid: {', '.join(module.options)}")
            return
        if name == "PERMISSION" and value.lower() not in ("true", "false"):
            console.print("[red]PERMISSION expects true or false.[/]")
            return
        self.state.values[name] = value.lower() if name == "PERMISSION" else value
        console.print(f"{name} => {self.state.values[name]}")

    def _unset(self, args: list[str], console: Console) -> None:
        module = self._active()
        if module is None:
            console.print("[red]No module selected. Use 'use <module>' first.[/]")
            return
        if len(args) != 1:
            console.print("[red]Usage: unset <OPTION>[/]")
            return
        name = args[0].upper()
        if name not in module.options:
            console.print(f"[red]Unknown option: {name}[/]")
            return
        self.state.values.pop(name, None)
        console.print(f"{name} => {module.options[name].default}")

    def _run(self, args: list[str], console: Console) -> None:
        if args:
            console.print("[red]Usage: run[/]")
            return
        module = self._active()
        if module is None:
            console.print("[red]No module selected. Use 'use <module>' first.[/]")
            return
        target = self._current_value("TARGET").strip()
        if not target:
            console.print("[red]TARGET not set.[/]")
            return
        try:
            timeout = int(self._current_value("TIMEOUT"))
        except ValueError:
            console.print("[red]TIMEOUT must be an integer.[/]")
            return
        targets = [t for t in re.split(r"[\s,]+", target) if t]
        output = self._current_value("OUTPUT").strip()
        kwargs = {
            "timeout": timeout,
            "no_cache": self._current_value("NO_CACHE") == "true",
            "output": Path(output) if output else None,
            "fmt": self._current_value("FORMAT"),
            "permission_granted": self._current_value("PERMISSION") == "true",
            "confirm": self._confirm,
        }
        if module.name == "scan":
            kwargs["ports"] = self._current_value("PORTS")
            code = self._execute_scan(targets, **kwargs)
        else:
            code = self._execute_web(targets[0], **kwargs)
        console.print("[green]Done.[/]" if code == 0 else "[red]Done with errors.[/]")
```

- [ ] **Step 4: Run the console tests**

Run: `python -m pytest tests/test_console.py -v`
Expected: all 22 tests pass.

- [ ] **Step 5: Commit**

```bash
git add blacklight/console.py tests/test_console.py
git commit -m "feat: console command runner (use/set/unset/run/back)"
```

---

### Task 3: `ConsoleApp` REPL loop, entry points, dependency, version bump

**Files:**
- Modify: `blacklight/console.py` (append `ConsoleApp`)
- Modify: `blacklight/paths.py` (add `CONSOLE_HISTORY`)
- Modify: `blacklight/cli.py` (callback → entry with `invoke_without_command=True`; add `console` command)
- Modify: `pyproject.toml`, `blacklight/__init__.py`, `tests/test_cli.py` (version 0.2.0)
- Modify: `docs/superpowers/specs/2026-08-03-console-mode-design.md` (banner placement wording)
- Test: `tests/test_console.py` (REPL smoke), `tests/test_cli.py` (entry points)

**Interfaces:**
- Consumes: `CommandRunner`, `SCAN_MODULE`, `WEB_MODULE` from Task 2; `execute_scan`/`execute_web` from Task 1; `paths` (adds `CONSOLE_HISTORY`).
- Produces:

```python
class ConsoleApp:
    def __init__(self, *, execute_scan: Callable[..., int],
                 execute_web: Callable[..., int],
                 confirm: Callable[[str], bool] | None = None) -> None: ...
    def run(self) -> int: ...
```

CLI: `blacklight console` command; bare `blacklight` runs the console; `blacklight-cli` version `0.2.0`.

- [ ] **Step 1: Write the failing entry-point tests**

Append to `tests/test_console.py`:

```python
from typer.testing import CliRunner

from blacklight.cli import app

runner = CliRunner()


def test_console_command_piped_session(monkeypatch):
    seen = []

    def fake_scan(targets, **kwargs):
        seen.append((targets, kwargs))
        return 0

    monkeypatch.setattr("blacklight.cli.execute_scan", fake_scan)
    result = runner.invoke(
        app, ["console"],
        input="use scan\nset TARGET 192.168.1.10\nrun\nexit\n",
    )
    assert result.exit_code == 0
    assert "modules loaded (scan, web)" in result.output
    assert "Type 'help'" in result.output
    assert "Using module scan" in result.output
    assert len(seen) == 1
    targets, kwargs = seen[0]
    assert targets == ["192.168.1.10"]
    assert kwargs["permission_granted"] is False


def test_bare_invocation_enters_console(monkeypatch):
    monkeypatch.setattr("blacklight.cli.execute_scan", lambda *a, **k: 0)
    result = runner.invoke(app, [], input="modules\nexit\n")
    assert result.exit_code == 0
    assert "██████╗" in result.output
    assert "modules loaded" in result.output
    assert "scan" in result.output
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_console.py -v`
Expected: the two new tests FAIL (missing command `console`, and bare invocation exits with code 2 "Missing command").

- [ ] **Step 3: Add `paths.CONSOLE_HISTORY`**

In `blacklight/paths.py`, after `SCAN_LOG`:

```python
CONSOLE_HISTORY = HOME_DIR / "console_history"
```

- [ ] **Step 4: Add `ConsoleApp` to `blacklight/console.py`**

Append to `blacklight/console.py`. The existing import block (Task 2) is:

```python
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TextIO

from rich.console import Console
```

Add the two lines below right after `from rich.console import Console`:

```python
from blacklight import __version__, paths
from blacklight import theme
```

Note: `blacklight/console.py` only imports `blacklight` package leaf modules — never `cli` — so there is no import cycle (and `cli.py` imports `console` lazily inside command handlers).

Then append:

```python
class ConsoleApp:
    """REPL loop: interactive (prompt_toolkit) or piped (plain input)."""

    def __init__(
        self,
        *,
        execute_scan: Callable[..., int],
        execute_web: Callable[..., int],
        confirm: Callable[[str], bool] | None = None,
    ) -> None:
        self._confirm = confirm or self._confirm_plain
        self.runner = CommandRunner(
            execute_scan=execute_scan,
            execute_web=execute_web,
            confirm=self._confirm,
        )

    def run(self) -> int:
        paths.ensure_dirs()
        self._print_header()
        if sys.stdin.isatty():
            self._run_interactive()
        else:
            self._run_piped()
        return 0

    def _print_header(self) -> None:
        names = ", ".join(self.runner.state.modules)
        console = Console()
        console.print(f"[bold {theme.ACCENT}]blacklight-cli[/] v{__version__} - "
                      f"{len(self.runner.state.modules)} modules loaded ({names})")
        console.print("Type 'help' for commands.")

    def _confirm_plain(self, message: str) -> bool:
        answer = input(f"{message} [y/N]: ")
        return answer.strip().lower() in ("y", "yes")

    def _run_piped(self) -> None:
        for line in sys.stdin:
            if self.runner.execute(line, sys.stdout):
                break

    def _run_interactive(self) -> None:
        from prompt_toolkit import HTML, PromptSession
        from prompt_toolkit.completion import WordCompleter
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.patch_stdout import patch_stdout

        words = [
            "help", "modules", "use", "show", "options", "set", "unset",
            "run", "back", "exit", "quit",
        ]
        for module in self.runner.state.modules.values():
            words.extend([module.name, *module.options])
        session = PromptSession(
            completer=WordCompleter(words, ignore_case=True),
            history=FileHistory(str(paths.CONSOLE_HISTORY)),
        )
        with patch_stdout():
            while True:
                try:
                    line = session.prompt(HTML(self._prompt_html()))
                except (EOFError, KeyboardInterrupt):
                    break
                if self.runner.execute(line, sys.stdout):
                    break
        print()

    def _prompt_html(self) -> str:
        active = self.runner.state.active
        if active is None:
            return "<ansicyan>blacklight</ansicyan> > "
        return (f"<ansicyan>blacklight</ansicyan> "
                f"<ansipurple>({active})</ansipurple> > ")
```

- [ ] **Step 5: Add the `console` command and bare-invocation entry to `blacklight/cli.py`**

1. Replace the callback (lines 37-40) with:

```python
@app.callback(invoke_without_command=True)
def _entry(ctx: typer.Context) -> None:
    """Show the brand banner, then run the console when no subcommand was given."""
    theme.print_banner(console)
    if ctx.invoked_subcommand is None:
        from blacklight.console import ConsoleApp

        ConsoleApp(execute_scan=execute_scan, execute_web=execute_web).run()
```

2. Add the `console` command right before the `version` command:

```python
@app.command()
def console() -> None:
    """Start an interactive scan console (same as running 'blacklight' bare)."""
    from blacklight.console import ConsoleApp

    ConsoleApp(execute_scan=execute_scan, execute_web=execute_web).run()
```

- [ ] **Step 6: Run the console + CLI tests**

Run: `python -m pytest tests/test_console.py tests/test_cli.py -v`
Expected: all pass. Note the banner is printed by the app callback, so `blacklight console` output contains the banner once, then the header; `blacklight version` still prints the banner and `blacklight-cli 0.1.0` (still hardcoded for now).

- [ ] **Step 7: Bump version to 0.2.0 and update the version test**

1. `pyproject.toml`: change line 7 to `version = "0.2.0"`.
2. `blacklight/__init__.py`: change to `__version__ = "0.2.0"`.
3. `tests/test_cli.py`: replace `from blacklight.cli import app, run_scan` with `from blacklight.cli import app, execute_scan, execute_web, run_scan` and add `from blacklight import __version__`; then update `test_version_command`:

```python
def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert f"blacklight-cli {__version__}" in result.output
```

- [ ] **Step 8: Add prompt_toolkit to pyproject and install**

`pyproject.toml` dependencies become:

```toml
dependencies = [
    "typer>=0.12",
    "rich>=13.7",
    "jinja2>=3.1",
    "requests>=2.31",
    "prompt_toolkit>=3",
]
```

Run: `python -m pip install -e .`
Expected: installs cleanly, `prompt_toolkit` now available.

- [ ] **Step 9: Fix the spec's banner wording and commit**

In `docs/superpowers/specs/2026-08-03-console-mode-design.md`, replace the line:

```
- On first start: print `theme.print_banner(console)` then header
  `blacklight-cli v0.2.0 — 2 modules loaded (scan, web)` + "Type 'help'…".
```

with:

```
- The app callback prints the banner (once, for every invocation); the
  console then prints the header `blacklight-cli v0.2.0 — 2 modules loaded
  (scan, web)` + "Type 'help'…".
```

Run the full suite: `python -m pytest` → Expected: all ~184 pass (160 + 2 console entry tests + 22 console core tests).

Commit:

```bash
git add blacklight/console.py blacklight/paths.py blacklight/cli.py \
        pyproject.toml blacklight/__init__.py tests/test_console.py tests/test_cli.py \
        docs/superpowers/specs/2026-08-03-console-mode-design.md
git commit -m "feat: interactive console mode (v0.2.0)"
```

---

### Task 4: Integration verification

**Files:**
- Test: full suite; manual smoke commands

- [ ] **Step 1: Full test suite**

Run: `python -m pytest`
Expected: all tests pass (~184; no failures, no collection errors).

- [ ] **Step 2: Verify CLI behavior is unchanged**

Run each and check exit code + output:

```powershell
blacklight version
blacklight scan --help
blacklight web --help
blacklight console --help
```

Expected: `version` prints banner + `blacklight-cli 0.2.0`; the help outputs list the flags/commands; `--help` on `blacklight` itself shows the command list with `console` and no console session.

- [ ] **Step 3: Piped console smoke**

Run: `"modules`nexit" | blacklight console`
Expected: banner, header `v0.2.0 - 2 modules loaded (scan, web)`, module listing, and a clean exit (code 0, no traceback).

Run: `"use scan`nshow options`nset PERMISSION maybe`nexit" | blacklight console`
Expected: options table shown; `PERMISSION expects true or false.` error; clean exit.

- [ ] **Step 4: Interactive smoke (requires a real terminal — ask the user)**

Run: `blacklight` and `blacklight console`.
Expected: styled `blacklight > ` prompt, tab completion for `use`/`set` options, arrow-key history, purple `blacklight (scan) > ` prompt after `use scan`, and `exit` returns to the shell.

- [ ] **Step 5: Update the SDD ledger**

Append the console-mode task outcomes to `.superpowers/sdd/sdd.md` (task list with statuses, per the existing format), noting: refactor (Task 1), core runner (Task 2), REPL + entry points + v0.2.0 (Task 3), verification (Task 4).

- [ ] **Step 6: Commit any leftovers**

```bash
git status
git add -A
git commit -m "chore: console mode integration notes"
```

(If nothing is left, skip this commit.)
