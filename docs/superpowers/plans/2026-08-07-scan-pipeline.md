# One Scan Pipeline (engine seam) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the duplicated `scan`/`web` orchestration into one deep `blacklight/engine.py` seam — a typed `ScanResult`, one `engine.run()` orchestrator, and two executor adapters (`NetworkScan`, `WebScan`) consumed by cli, console, TUI, and history.

**Architecture:** A new `blacklight/engine.py` owns the whole scan spine — guardrails verify → confirm → execute → log → record → render → export — behind one entry `run(executor, targets, params, *, confirm, on_progress)`. The two genuinely-different guts become adapter objects (`NetworkScan`, `WebScan`), each exposing `verify(...) -> Verdict` and `run(...) -> ScanResult`. `ScanResult` carries `kind`, the target, `generated`, both finding lists, and a per-kind typed meta (`NetworkMeta` / `WebMeta`), killing the string-keyed `meta` dict that `history.record_scan`, `reporter`, and tests branch on by `kind`. `history.record_scan` and `reporter.render_terminal`/`export_report` change to consume the typed result. cli.py becomes a thin typer shell; console.py and tui wire to the single injected orchestrator.

**Tech Stack:** Python 3.11+, existing `typer`/`rich`/`requests`, no new dependencies. Tests run with `pytest` (`python -m pytest -q`).

## Global Constraints

- Preserve every user-facing behavior: exit codes, terminal report text, JSON/HTML/Markdown export payload shapes, `~/.blacklight/scan.log` line formats, and the DB schema in `history.py` (do NOT alter the `scans`/`findings` tables or their meaning).
- `Finding` (network) and `WebFinding` (web) remain two distinct types behind the `ScanResult` envelope — do not unify them.
- `history.py`'s storage layer and its rendering calls (render_list/render_diff/render_trend) are untouched except `record_scan`'s signature; the full store/rendering split is a later pass and out of scope here.
- `guardrails.py`, `scoring.py`, `scanner.py`, `cve_matcher.py`, `enrichment.py`, `web/http.py`, `web/checks.py`, `web/fingerprint.py`, `web/models.py`, `theme.py`, `paths.py` are not modified.
- `engine.run` is the ONLY place that calls `confirm`; never re-declare `on_progress` stages in consumers.
- Kind values are the strings `"scan"` and `"web"` (matches the history `kind` column and the console `use`/module names).
- Commit after every task. Run the full suite (`python -m pytest -q`) at the end of each task; it must be 100% green before moving on.
- No new files outside `blacklight/engine.py`, `tests/test_engine.py`, and the edits below.

---

## File Map

| File | Change | Responsibility after |
|---|---|---|
| `blacklight/engine.py` | **new** | `ScanParams`, `NetworkMeta`, `WebMeta`, `ScanResult`, `ScanExecutor` protocol, `NetworkScan`, `WebScan`, `run()` orchestrator, module-level `console`, `_set_console()`, `port_for_url()`, `_log_result()` |
| `blacklight/history.py` | modify | `record_scan(result: ScanResult, permission: bool)` — consumes the typed result |
| `blacklight/reporter.py` | modify | `render_terminal(result, console)` and `export_report(result, fmt, output)` consume `ScanResult`; `host_risk_table`, `findings_table`, `web_findings_table` unchanged |
| `blacklight/cli.py` | modify | thin typer shell; `execute_scan`/`execute_web` deleted; `run_scan`/`run_web_scan` imports gone |
| `blacklight/console.py` | modify | `CommandRunner` holds one injected `run` callable; `ConsoleApp` wires `engine.run` |
| `blacklight/tui/app.py` | modify | `BlacklightApp(run=...)` single injected orchestrator |
| `blacklight/tui/views.py` | modify | `capture_engine_output` swaps `engine.console`; `RunScreen` calls the single `run` |
| `blacklight/web/engine.py` | delete | moved into `WebScan` adapter |
| `blacklight/web/__init__.py` | modify | drop `run_web_scan`/`WebResult` re-exports |
| `tests/test_engine.py` | new | adapter + orchestrator + meta tests (migrated from test_cli.py + test_web_engine.py) |
| `tests/test_cli.py`, `tests/test_cli_web.py` | modify | thinned to typer-shell tests; pipeline tests migrate to test_engine.py |
| `tests/test_console.py`, `tests/test_tui.py` | modify | inject single `run` callable |
| `tests/test_reporter.py`, `tests/test_history.py` | modify | build `ScanResult` objects |
| `CONTEXT.md` | modify | keep domain glossary current |

---

### Task 1: `engine.py` typed result and executor adapters

**Files:**
- Create: `blacklight/engine.py`
- Test: `tests/test_engine.py`

**Interfaces:**
- Produces: `ScanParams`, `NetworkMeta`, `WebMeta`, `ScanResult`, `ScanExecutor` (Protocol), `NetworkScan`, `WebScan`, `port_for_web(url)`, module-level `console`. `NetworkScan.run(targets, params, on_progress=None) -> ScanResult`, `WebScan.run(...) -> ScanResult`. `ScanResult` fields: `kind`, `target`, `generated`, `findings`, `web_findings`, `meta`.
- Consumes: from `scanner` (`scan_hosts`, `find_nmap`, `ScanRecord`), `cve_matcher` (`NvdClient`, `build_findings`, `Finding`, `CVE`), `enrichment` (`enrich_findings`), `guardrails` (`Verdict`, `verify_targets`, `verify_web_target`, `normalize_web_url`, `resolve_hostname`), `web.http` (`Page`, `fetch_page`, `probe`), `web.checks` (`CHECKS`), `web.fingerprint` (`fingerprint_page`, `Fingerprint`), `web.models` (`WebFinding`), `cpe_map` (`service_to_cpe`), `paths`, `theme`.

The task is pure: create the types and the two adapters (moving the bodies of `cli.run_scan` and `web/engine.run_web_scan` verbatim into the adapters, returning `ScanResult`). Nothing else changes; all existing tests stay green because `cli.py`/`web/engine.py` are untouched this task.

- [ ] **Step 1: Write the failing tests**

`tests/test_engine.py`:

```python
"""Scan pipeline adapter tests (engine.seam)."""

from types import SimpleNamespace

import pytest

from blacklight.engine import (
    NetRouteScan,
    ScanResult,
    WebScan,
    port_for_url,
)
from blacklight.web.models import WebFinding


class _FakeClient:
    def __init__(self, *a, **k):
        pass

    def lookup(self, cpe):
        return []


def _page(url="https://example.com/", status=200, headers=None, text="hello"):
    return Page(url=url, status=status, headers=headers or {}, text=text)


def test_port_for_url():
    assert port_for_url("http://example.com") == 80
    assert port_for_url("https://example.com") == 443
    assert port_for_url("https://example.com:8443") == 8443


def test_network_scan_runs_pipeline_and_meta(monkeypatch):
    from blacklight.scanner import ScanRecord

    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", lambda *a, **k: records)
    params = SimpleNamespace(ports="22", timeout=30, no_cache=False)
    result = NetMetaScan().run(["192.168.1.10"], params)
    assert isinstance(result, ScanResult)
    assert result.kind == "scan"
    assert result.meta.hosts_scanned == 1
    assert result.meta.services_found == 1
    assert result.meta.findings_count == 0
    assert result.findings == []
    assert "generated" in result.meta.generated


def test_web_scan_runs_checks_and_meta(monkeypatch):
    page = _page(text='<a href="/search?q=x">S</a>', headers={"X-Frame-Options": "DENY"})
    monkeypatch.setattr("blacklight.engine.web_http.fetch_page", lambda *a, **k: page)
    monkeypatch.setattr("blacklight.engine.web_http.probe",
                        lambda url, params=None, timeout=30, **k:
                        type("P", (), {"status": 200, "text": "ok"})())
    monkeypatch.setattr("blacklight.engine.guardrails("resolve_hostname",
                        lambda host: "192.168.1.10")
    monkeypatch.setattr("blacklight.engine.NvdClient", _FakeClient)
    params = SimpleNamespace(timeout=30, no_cache=False)
    result = WebScan().run(["https://example.com/"], params)
    assert result.kind == "web"
    assert result.target == "https://example.com/"
    assert result.meta.checks_run > 0
    assert result.meta.hosts == "example.com"
    assert result.findings == []


def test_web_scan_cve_findings_from_fingerprint(monkeypatch):
    from blacklight.cve_matcher import CVE

    page = _page(headers={"Server": "Apache/2.4.49"})
    monkeypatch.setattr("blacklight.engine.web_http.fetch_page", lambda *a, **k: page)
    monkeypatch.setattr("blacklight.engine.web_http.probe",
                        lambda *a, **k: type("P", (), {"status": 404, "text": "no"})())
    monkeypatch.setattr("blacklight.engine.guardrails.resolve_hostname",
                        lambda host: "192.168.1.10")

    class FindCve:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            assert cpe.startswith("cpe:2.3:a:apache:http_server:2.4.49")
            return [CVE("CVE-2021-41773", "Path traversal", 9.8, "critical", "2.4.50")]

    monkeypatch.setattr("blacklight.engine.NvdClient", FindCve)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    result = WebScan().run(["https://example.com/"],
                           SimpleNamespace(timeout=30, no_cache=False))
    cve_findings = [f for f in result.web_findings if f.category == "fingerprint"]
    assert len(cve_findings) == 1
    assert cve_findings[0].cve_id == "CVE-2021-41773"
    assert result.meta.cve_findings == 1
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `python -m pytest tests/test_engine.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.engine'`.

- [ ] **Step 3: Create `blacklight/engine.py` — types, meta, adapter stubs**

```python
"""One scan pipeline: a typed ScanResult and two executor adapters.

The orchestrator (``engine.run``) in this module is the single seam that
runs a whole scan: guardrails verify -> confirm -> scan -> log -> record
-> render -> export. The two genuine variants (network, web) live behind
it as adapter objects: each exposes ``verify`` (guardrails verdict) and
``run`` (produces a typed ``ScanResult``).
"""

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from blacklight import enrichment, guardrails, scanner, theme
from blacklight.cve_matcher import Finding, NvdClient, build_findings
from blacklight.guardrails import Verdict
from blacklight.web import http
from blacklight.web.checks import CHECKS
from blacklight.web.fingerprint import fingerprint_page
from blacklight.web.models import WebFinding


@dataclass
class ScanParams:
    """One run's options: guardrail signal + executor tuning + output."""

    permission_granted: bool = False
    timeout: int = 30
    no_cache: bool = False
    ports: str | None = None
    output: Path | None = None
    fmt: str = "html"


@dataclass
class NetworkMeta:
    targets: str
    hosts_scanned: int
    services_found: int
    findings_count: int
    generated: str


@dataclass
class WebMeta:
    url: str
    host: str
    resolved_ip: str
    checks_run: int
    checks_errored: int
    cve_findings: int
    generated: str


@dataclass
class ScanResult:
    """Typed outcome of a scan pipeline run (shared by history/reporter/UI)."""

    kind: str
    target: str
    generated: str
    findings: list[Finding]
    web_findings: list[WebFinding]
    meta: NetworkMeta | WebMeta


class ScanExecutor:
    """Contract for a scan kind: guardrail verification + a pipe run."""

    kind: str = ""

    def verify(self, targets: list[str], permission_granted: bool) -> Verdict:
        raise NotImplementedError

    def run(
        self,
        targets: list[str],
        params
        params: ScanParams,
        progress: Callable[[str, int | None, int | None], None] | None = None,
    ) -> ScanResult:
        raise NotImplementedError


class NetworkScan(ScanExecutor):
    """Adapter for the nmap -> CVE -> enrich pipeline."""

    kind = "scan"

    def verify(self, targets: list[str], permission_granted: bool) -> Verdict:
        return guardrails.verify_targets(targets, permission_granted)

    def run(
        self,
        targets: list[str],
        params: ScanParams,
        progress: Callable[[str, int | None, int | None], None] | None = None,
    ) -> ScanResult:
        if progress:
            progress("scanning", None, None)
        with Progress(
            SpinnerColumn(spinner_name="aesthetic", style=theme.ACCENT),
            TextColumn("[cyan]{task.description}"),
            BarColumn(
                bar_width=None,
                complete_style=theme.???,
                finished_style=theme.???,
            ),
        ) as bar:
            bar.add_task("Scanning hosts with nmap...", total=None)
            records = scanner.scan_hosts(targets, params.ports or "1-1024", params.timeout)
            phase = bar.add_task("Matching CVEs against NVD...", total=len(records))
            client = NvdClient(
                api_key=os.environ.get("BLACKLIGHT_NVD_KEY"),
                no_cache=params.no_cache,
            )
            findings: list[Finding] = []
            if progress:
                progress("matching", 0, len(records))
            for index, record in enumerate(records):
                findings.extend(build_findings([record], client))
                bar.advance(phase)
                if progress:
                    progress("matching", index + 1, len(records))
            bar.add_task("Enriching with EPSS/KEV...", total=None)
            if progress:
                progress("enriching", None, None)
            findings = enrichment.enrich_findings(findings)
        generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return ScanResult(
            kind=self.kind,
            target=", ".join(targets),
            generated=generated,
            findings=findings,
            web_findings=[],
            meta=NetworkMeta(
                targets=", ".join(targets),
                hosts_scanned=len({r.host for r in records}),
                services_found=len(records),
                findings_count=len(findings),
                generated=generated,
            ),
        )


def port_for_url(url: str) -> int:
    """Default port for a URL: explicit port, else 443/80 by scheme."""
    parsed = urllib.parse.urlparse(url)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _hostname(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""


class WebScan(ScanExecutor):
    """Adapter for the web scan: checks + fingerprint -> CVE -> enrich."""

    kind = "web"

    def verify(self, targets: list[str], permission_granted: bool) -> Verdict:
        url = guardrails.normalize_web_url(targets[0])
        return guardrails.verify_web_target(url, permission_granted)

    def run(
        self,
        targets: list[str],
        params: ScanParams,
        progress: Callable[[str, int | None, int | None], None] | None = None,
    ) -> ScanResult:
        url = guardrails.normalize_web_url(targets[0])
        page = http.fetch_page(url, params.timeout)
        findings: list[WebFinding] = []
        errored = 0

        def probe(target_url: str, query: dict | None = None):
            return http.probe(target_url, query, params.timeout)

        for name, check in CHECKS.items():
            try:
                finding = check(page, probe)
            except Exception:
                errored += 1
                continue
            if finding is not None:
                findings.append(finding)

        host = _hostname(page.url)
        resolved = guardrails.resolve_hostname(host) or host
        findings.extend(self._cve_findings(url, resolved, page, params.no_cache))
        generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return ScanResult(
            kind=self.kind,
            target=url,
            generated=generated,
            findings=[],
            web_findings=findings,
            meta=WebMeta(
                url=url,
                host=host,
                resolved_ip=resolved,
                checks_run=len(CHECKS),
                checks_errored=errored,
                cve_findings=sum(1 for f in findings if f.category == "fingerprint"),
                generated=generated,
            ),
        )

    def _cve_findings(self, url: str, host: str, page: http.Page,
                      no_cache: bool) -> list[WebFinding]:
        fingerprints = fingerprint_page(page)
        if not fingerprints:
            return []
        client = NvdClient(api_key=os.environ.get("BLACKLIGHT_NVD_KEY"),
                           no_cache=no_cache)
        matched: list[Finding] = []
        for fp in fingerprints:
            cpe = cpe_map.service_to_cpe(fp.service, fp.version)
            if cpe is None:
                continue
            from blacklight.scanner import ScanRecord

            record = ScanRecord(host=host, port=port_for_url(url), protocol="tcp",
                                service=fp.service, version=fp.version)
            matched.extend(build_findings([record], client))
        matched = enrichment.enrich_findings(matched)
        return [
            WebFinding(url=url, category="fingerprint", detail=f.description,
                       severity=f.severity, evidence=f.cpe,
                       cve_id=f.cve_id, epss=f.epss, in_kev=f.in_kev)
            for f in matched
        ]
```

Run: `python -m pytest tests/test_engine.py -q`
Expected: PASS (all three tests).

- [ ] **Step 4: run the full suite**

Run: `python -m pytest -q`
Expected: PASS — nothing consumes the new module yet.

- [ ] **Step 5: Commit**

```bash
git add blacklight/engine.py tests/test_engine.py
git commit -m "feat: engine adapters produce a typed ScanResult (scan + web)"
```

---

### Task 2: the `run()` orchestrator — the scan spine moves into engine

**Files:**
- Modify: `blacklight/engine.py` (add `run`, `_log_result`, `console`, `set_console`)
- Modify: `blacklight/cli.py` (`execute_scan`/`execute_web` become thin adapters into `engine.run`; delete `run_scan`/`_log_scan`/`_log_web_scan`)
- Modify: `tests/test_engine.py` (add orchestrator tests), `tests/test_cli.py` (update monkeypatch targets for the moved pipeline)

**Interfaces:**
- Consumes: `ScanResult` (Task 1), `reporter.render_terminal`, `reporter.export_report`, `history.record_scan`, `scanner.find_nmap`, `theme`.
- Produces: `engine.run(executor, targets, params, *, confirm, on_progress=None, console=None) -> int`, `engine.set_console(console)`, `engine.console`.

The orchestration that lives in `execute_scan`/`execute_web` (verify → blocked messages → confirm → no-target check → nmap present check → fmt validation → suffix heuristic → run → log → record → render → export) moves into `engine.run`. `cli.execute_scan`/`execute_web` shrink to one call into the orchestrator. The `record_scan` and `render_terminal`/`export_report` calls still use the OLD dict signatures this task; they only get the typed `ScanResult` in Tasks 3–4.

- [ ] **Step 1: Write the failing orchestrator tests**

Append to `tests/test_engine.py`:

```python
def _records():
    from blacklight.scanner import ScanRecord

    return [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                       service="OpenSSH", version="9.6p1")]


def _monkey_scan(monkeypatch, tmp_path, records=None, fake_client=None):
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts",
                        lambda *a, **k: records or [])
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.os.environ", {})
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    monkeypatch.setattr("blacklight.engine.NvdClient", fake_client or _FakeClient)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings",
                        lambda findings, **k: findings)


def _params(**extra):
    from blacklight.engine import ScanParams

    return ScanParams(permission_granted=False, output=None, fmt="html",
                      timeout=30, no_cache=False, **extra)


def never_confirm(message):
    raise AssertionError("confirm must not be called")


def test_run_blocks_public_target_without_permission(monkeypatch, tmp_path, capsys):
    from blacklight.engine import NetworkScan, run

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    code = run(NetworkScan(), ["8.8.8.8"],
               _params(permission_granted=False), confirm=never_confirm)
    assert code == 1
    assert "Blocked" in capsys.readouterr().out


def test_run_aborts_when_confirm_declines(monkeypatch, tmp_path, capsys):
    from blacklight.engine import NetworkScan, run

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    calls = []

    def declining(message):
        calls.append(message)
        return False

    code = run(NetworkScan(), ["8.8.8.8"],
               _params(permission_granted=True), confirm=declining)
    assert code == 1
    assert calls
    assert "Aborted" in capsys.readouterr().out


def test_run_private_target_skips_confirm_and_records_history(monkeypatch, tmp_path):
    from blacklight import history
    from blacklight.engine import NetworkScan, run

    _monkey_scan(monkeypatch, tmp_path, records=_records())
    code = run(NetworkScan(), ["192.168.1.10"],
               _params(ports="22"), confirm=never_confirm)
    assert code == 0
    rows = history.list_recent()
    assert len(rows) == 1
    assert rows[0].kind == "scan"
    assert rows[0].hosts == 1


def test_run_exports_json(monkeypatch, tmp_path, capsys):
    from blacklight.engine import NetworkScan, run

    _monkey_scan(monkeypatch, tmp_path, records=_records())
    out = tmp_path / "report.json"
    code = run(NetworkScan(), ["192.168.1.10"],
               _params(output=out, fmt="json"), confirm=never_confirm)
    assert code == 0
    assert out.exists()
    assert "Report written to" in capsys.readouterr().out


def test_run_returns_1_on_upstream_error(monkeypatch, tmp_path, capsys):
    import requests

    from blacklight.engine import NetworkScan, run

    def boom(*a, **k):
        raise requests.ConnectionError("unable to reach nvd.nist.gov")

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", boom)
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    code = run(NetworkScan(), ["192.168.1.10"],
               _params(), confirm=never_confirm)
    assert code == 1
    assert "Scan failed" in capsys.readouterr().out
    assert not (tmp_path / "scan.log").exists()
```

Note: `_records()` is `_records = _schedule(...)` — define `def _records(): return _records_of_one_host()`; simplest is to reuse the function from Task 1. Write:

```python
def _records():
    from blacklight.scanner import ScanRecord

    return [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                       service="OpenSSH", version="9.6p1")]
```

- [ ] **Step 2: run to verify failure**

Run: `python -m pytest tests/test_engine.py -q`
Expected: FAIL with `AttributeError: module 'black_light.engine' has no attribute 'run'`.

- [ ] **Step 3: implement `run` and the console plumbing**

In `blacklight/engine.py`, add module state and the orchestrator:

```python
console = theme.make_console()


def set_console(c: Console) -> None:
    """Point the engine's shared console (TUI/--color swap the sink)."""
    global console
    console = c
```

At the top of `engine.py`, change import to also bring in `Console` from rich, `history`, `paths`, `reporter`, `subprocess`, `requests`:

```python
import subprocess

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from blacklight import enrichment, history, guardrails, paths, scanner, theme
from blacklight.cve_matcher import Finding, NvdClient, build_findings
from blacklight.reporter import export_report, render_terminal
from blacklight.web import web_checks
```

And the `run` orchestrator itself:

```python
def run(
    executor: ScanExecutor,
    targets: list[str],
    params: ScanParams,
    *,
    confirm: Callable[[str], bool],
    on_progress: Callable[[str, int | None, int | None], None] | None = None,
    console: Console | None = None,
) -> int:
    """Run one scan end-to-end. Returns exit code (0 or 1)."""
    console = console or globals()["console"]
    paths.ensure_dirs()
    verdict = executor.verify(targets, params.permission_granted)
    for blocked in verdict.blocked:
        console.print(f"[red]Blocked:[/] {blocked} is not a scannable target. "
                      "Pass --i-have-permission to allow non-private targets.")
    if verdict.needs_confirmation:
        names = ", ".join(verdict.needs_confirmation)
        if not confirm(f"Target(s) {names} are public. Are you authorized to scan them?"):
            console.print("[yellow]Aborted.[/]")
            return 1
    scannable = verdict.allowed + verdict.needs_confirmation
    if not scannable:
        console.print("[red]No scannable targets.[/]")
        return 1
    if executor.kind == "scan" and scanner.find_nmap() is None:
        console.print("[red]nmap not found.[/] Install it with one of:\n"
                      "  apt:   sudo apt install nmp\n"
                      "  brew:  brew install nmap\n"
                      "  choco: choco install nmap")
        return 1
    if params.fmt not in ("html", "markdown", "json"):
        console.print("[red]Invalid format.[/] Choose html, markdown, or json.")
        return 1
    if params.output is not None and params.fmt == "html" and params.output.suffix in (".md", ".json"):
        params.fmt = "markdown" if params.output.suffix == ".md" else "json"

    try:
        result = executor.run(scannable, params, on_progress)
    except (
        requests.RequestException,
        subprocess.TimeoutExpired,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        console.print(f"[red]{'Web scan' if executor.kind == 'web' else 'Scan'} failed:[/] {exc}")
        return 1
    _log_result(executor.kind, result, params.permission_granted)
    try:
        history.record_scan("scan" if executor.kind == "scan" else "web",
                            result, params.permission_granted)
    except (OSError, sqlite3.Error) as exc:
        console.print(f"[yellow]Could not record scan history:[/] {exc}")
    render_terminal(result, console)
    if params.output is not None:
        try:
            export_report(result, params.fmt, params.output)
        except (OSError, ValueError) as exc:
            console.print(f"[red]Report export failed:[/] {exc}")
            return 1
        console.print(f"Report written to [bold]{params.output}[/]")
    return 0


def _log_result(kind: str, result: ScanResult, permission: bool) -> None:
    """Append one scan.log line per run; format differs by kind."""
    if kind == "scan":
        meta = result.meta
        line = (
            f"{result.generated} target={result.target} permission={permission} "
            f"hosts={meta.hosts_scanned} services={meta.services_found} "
            f"findings={meta.findings_count}\n"
        )
    else:
        meta = result.meta
        chunk = (
            f"target={result.target}"
        )
        line = (
            f"{meta.generated} url={result.target} permission={permission} "
            f"checks={meta.checks_run} errors={meta.checks_errored} "
            f"findings={meta.cve_findings}\n"
        )
    with paths.SCAN_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line)
```

Note: the orchestrator currently calls `history.record_scan(kind, result, permission)` and `reporter.render_terminal(result, console)` / `export_report(result, fmt, output)` with signatures that DON'T EXIST YET. To keep this task green, THOSE functions must be created with drop-in old-shape helpers for now; Tasks 3–4 replace them with the real typed signatures. So also add TEMPORARY adapter helpers in `reporter.py` and `history.py` (removed in Task 3/4) — no, simpler: keep the engine calling the CURRENT signatures for `record_scan`, `render_terminal`, `export_report`, converting the typed result back to the old arrangement at the call site. Add small projection functions in engine:

```python
def _legacy_meta(result: ScanResult) -> dict:
    """Project a ScanResult.meta back to the old dict for record/report."""
    if result.kind == "scan":
        m = result.meta
        return {"targets": m.targets, "hosts_scanned": m.hosts_scanned,
                "services_found": m.services_found, "findings_count": m.findings_count,
                "generated": m.generated}
    m = result.meta
    return {"url": m.url, "host": m.host, "resolved_ip": m.resolved_ip,
            "checks_run": m.checks_run, "checks_errored": m.checks_errored,
            "cve_findings": m.cve_findings, "generated": m.generated}
```

and call `render_terminal(result.findings, _legacy_meta(result), web_findings=result.web_findings or None, web_meta=(_legacy_meta(result) if result.kind == "web" else None))`, `export_report(findings, _legacy_meta(result), fmt, output, web_findings=result.web_findings or None, web_meta=(_legacy_meta(result) if result.kind == "web" else None))`, `history.record_scan(result.kind, result.target, permission, _legacy_meta(result), result.findings or result.web_findings)`. These temporary calls are replaced in Tasks 3 and 4.

- [ ] **Step 4: rerun the new engine tests**

Run: `python -m pytest tests/test_engine.py -q`
Expected: PASS for the orchestrator + adapter tests.

- [ ] **Step 5: rewire `cli.py` to delegate (no behavior change yet)**

Replace the bodies of `execute_scan` and `execute_web` with one-listers, keep the same params:

```python
def execute_scan(
    targets: list[str], *,
    ports: str, timeout: int, no_cache: bool,
    output: Path | None, fmt: str,
    permission_granted: bool, confirm: Callable[[str], bool],
    on_progress: Callable[[str, int | None, int | None], None] | None = None,
) -> int:
    """Run a network scan through the engine; returns process exit code."""
    params = ScanParams(permission_granted=permission_granted, timeout=timeout,
                        no_cache=no_cache, ports=ports, output=output, fmt=fmt)
    return engine.run(engine.NetworkScan(), targets, params,
                      confirm=confirm, on_progress=on_progress)
```

(Add `import blacklight.engine as engine` and `from blacklight.engine import ScanParams` at the top; remove `run_scan`, `_log_scan`, `_log_web_scan`, and the now-unused imports like `Progress/BarColumn/...` in cli.py.)

`execute_web` similarly:

```python
def execute_web(
    url: str, *,
    timeout: int, no_cache: bool,
    output: Path | None, fmt: str,
    permission_granted: bool, confirm: Callable[[str], bool],
) -> int:
    """Run a web scan through the orchestrator; returns process exit code."""
    params = ScanParams(permission_granted=permission_granted,
                        timeout=timeout, no_cache=no_cache,
                        output=output, fmt=fmt)
    return engine.run(engine.WebScan(), [url], params, confirm=confirm)
```

Update `tests/test_cli.py` monkeypatch targets:
- `blacklight.cli.scanner.scan_new` → stays (now called from `engine`, so change to `blacklight.engine.scanner.scan_hosts`)
- `blacklight.cli.scanner.find_nmap` → `blacklight.engine.scanner.find_nmap`
- `blacklight.cli.NvdClient` → `blacklight.engine.NvdClient`
- `blacklight.cli.enrichment.enrich_findings` → `blacklight.engine.enrichment.enrich_findings`
- `blacklight.cli.run_web_scan` → `blacklight.engine.WebScan.run` (or keep the existing mock shape by mocking `blacklight.engine.WebScan.run`)
- `blacklight.cli.paths.CACHE_DIR` / `blacklight.cli.paths.SCAN_LOG` → `blacklight.engine.paths.*`
- `blacklight.cli.guardrails.resolve_hostname` → `blacklight.engine.guardrails.resolve_hostname`

Also `tests/test_cli_web.py` similarly. Keep the typer-level expectations (exit codes, "Blocked", "Web scan failed", JSON exports). The `WEB_META` dict stays since `engine` still receives a dict projection this task (Task 4 removes it).

- [ ] **Step 6: full suite**

Run: `python -m pytest -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add blacklight/engine.py blacklight/cli.py tests/test_engine.py tests/test_cli.py tests/test_cli_web.py
git commit -m "feat: engine.run orchestrates scan+web; cli delegates"
```

---

### Task 3: `history.record_scan` takes the typed `ScanResult`

**Files:**
- Modify: `blacklight/history.py` (`record_scan` signature; internals now read typed fields)
- Modify: `blacklight/engine.py` (drop the `_legacy_meta` projection for `record_scan`)
- Modify: `tests/test_history.py`, `tests/test_console.py`, `tests/test_tui.py` (call sites build a `ScanResult`)

**Interfaces:**
- Consumes: `ScanResult` (Task 1).
- Produces: `history.record_scan(result: ScanResult, permission: bool) -> None`.

- [ ] **Step 1: write failing history tests (typed)**

`tests/test_history.py` — replace the dict-based `NET_META`/`WEB_META` usage in `record_scan` call sites with `ScanResult` fixtures. Add a helper module-level:

```python
from dataclasses import dataclass

from blacklight.engine import NetworkMeta, ScanParams, ScanResult, WebMeta
from blacklight.gameoff import scan_result_generator


def _scan_result(kind="scan", target="192.168.1.10", generated="2026-08-04T10:00:00+00:00",
                 findings=None, hosts=1, services=0, counts=0):
    findings = findings or []
    if kind == "scan":
        return ScanResult(kind=kind, target=target, generated=generated,
                          findings=findings, web_findings=[],
                          meta=NetworkMeta(targets=target, hosts_scanned=hosts,
                                           services_found=services, findings_count=counts,
                                           generated=generated))
    return ScanResult(kind=kind, target=target, generated=generated,
                      findings=[], web_findings=findings,
                      meta=WebMeta(url=target, host="example.com", resolved_ip="1.2.3.4",
                                   checks_run=1, checks_errored=0,
                                   cve_findings=len(findings), generated=generated))
```

Then update each `record_scan("scan", target, permission, NET_META, findings)` call to `record_scan(_scan(kind="scan", target=target, generated=..., findings=...), permission)`. The existing assertions on `rows[0].kind`, `hosts`, `scanned_at`, `findings` stay identical.

- [ ] **Step 2: run to see fail**

Run: `python -m pytest tests/test_history.py -q`
Expected: FAIL with `TypeError: record_scan() ... unexpected keyword ...` or similar.

- [ ] **Step 3: update `history.py`**

```python
def record_scan(result: ScanResult, permission: bool) -> None:
    """Persist one completed run (a typed ScanResult)."""
    conn = _connect()
    try:
        kind = result.kind
        if kind == "scan":
            meta = result.meta
            hosts, services = meta.hosts_scanned, meta.services_found
            count = meta.findings_count
            target = result.target
            findings = result.findings
        else:
            hosts, services, count = 0, 0, len(result.web_findings)
            target = result.target
            findings = result.web_findings
        cur = conn.execute(
            "INSERT INTO scans (kind, target, permission, scanned_at, hosts,"
            " services, findings_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (kind, target, 1 if permission else 0, meta.generated,
             hosts, services, count),
        )
        scan_id = cur.lastrowid
        for f in findings:
            if kind == "scan":
                values = (
                    scan_id, "scan", _network_fingerprint(f),
                    f.host, f.port, f.service or "", f.cve_id or "",
                    None, f.description, None, f.severity,
                    f.cvss_score, f.epss or 0.0, 1 if f.in_kev else 0,
                )
            else:
                values = (
                    scan_id, "web", _web_fingerprint(f),
                    None, None, None, f.cve_id or "",
                    f.category, f.detail, f.evidence, f.severity,
                    None, f.epss or 0.0, 1 if f.in_kev else 0,
                )
            conn.execute(
                "INSERT INTO findings (scan_id, kind, fingerprint, host, port,"
                " service, cve_id, category, detail, evidence, severity, cvss,"
                " epss, in_kev) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )
        conn.commit()
    finally:
        conn.close()
```

Update `blacklight/engine.py`: replace `history.record_scan("scan" if ..., result, permission)` with `history.record_scan(result, params.permission_granted)`.

Note: `record_scan` needs the local variable `meta` defined for the second branch — restructure to one `meta = result.meta` before the branch.

- [ ] **Step 4: update every other `record_scan` call site**

Sites: `tests/test_console.py` (three `record_scan("scan", ...)` + the history/trend tests), `tests/test_tui.py` (two `record_scan` calls + the diff test), `tests/test_cli.py` (history test fixtures). Replace each dict-based call with a `_scan(...)` ScanResult built from the same metadatas. Add the same `_scan` helper to those modules (or import from a shared helper in a `tests/helpers.py`). Simplest: define `_build_result(...)` in each test file.

- [ ] **Step 5: run the suite**

Run: `python -m pytest -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add blacklight/history.py blacklight/engine.py tests/test_history.py tests/test_console.py tests/test_tui.py tests/test_cli.py
git commit -m "feat: record_scan consumes typed ScanResult"
```

---

### Task 4: reporter takes the typed `ScanResult`

**Files:**
- Modify: `blacklight/reporter.py` (`render_terminal(result, console)`, `export_report(result, fmt, output)`)
- Modify: `blacklight/engine.py` (drop `_legacy_meta` for render/export)
- Modify: `tests/test_reporter.py` (build `ScanResult`s)

**Interfaces:**
- Consumes: `ScanResult` (Task 1).
- Produces: `render_terminal(result: ScanResult, console: Console | None = None) -> None`, `export_report(result: ScanResult, fmt: str, output: Path) -> Path`.

- [ ] **Step 1: write failing test**

In `tests/test_reporter.py`, replace `META` dict with a ScanResult builder and update all call sites:

```python
def _result(findings=None, web=False):
    from blacklight.engine import NetworkMeta, ScanResult, WebMeta

    findings = findings or []
    if not web:
        return ScanResult(kind="scan", target="192.168.1.10",
                          generated="2030-01-01T00:00:00+00:00", findings=findings,
                          web_findings=[],
                          meta=NetworkMeta(targets="192.168.1.10",
                                           hosts_scanned=len(findings) or 1,
                                           services_found=len(findings),
                                           findings_count=len(findings),
                                           generated="2030-01-01T00:00:00+00:00"))
    return ScanResult(kind="web", target="http://example.com/",
                      generated="2030-01-01T00:00:00+00:00", findings=[],
                      web_findings=findings,
                      meta=WebMeta(url="http://example.com/", host="example.com",
                                   resolved_ip="127.0.0.1", checks_run=18, checks_errored=0,
                                   cve_findings=0, generated="2030-01-01T00:00:00+00:00"))
```

Update each of:
- `render_terminal([_finding()], META, console=console)` → `render_terminal(_result([_finding()]), console=console)`
- `test_reporter_terminal_with_web_section`: `render_terminal(_web(), Console(file=out, width=160), web_findings=_web_findings(), web_meta={...})` → `render_terminal(_result(_web_findings(), web=True), Console(file=out, width=160))`
- `export_report([...], META, "json", ...)` → `export_report(_result([_finding()]), "json", path)`

- [ ] **Step 2: run to verify fail**

Run: `python -m pytest tests/test_reporter.py -q`
Expected: FAIL (`TypeError` on the new signature).

- [ ] **Step 3: update `reporter.py`**

```python
def _web_summary_text(web_findings: list[WebFinding], meta: WebMeta) -> str:
    return (
        f"[bold {ACCENT}]blacklight-cli[/] v{__version__} - web report\n"
        f"URL: [bold]{meta.url}[/] ({meta.resolved_ip}) | "
        f"Checks run: {meta.checks_run} | Checks errored: {meta.checks_errored} | "
        f"Web findings: {len(web_findings)} | Web risk score: {web_risk_score(web_findings):.1f}"
    )


def render_terminal(result: ScanResult, console: Console | None = None) -> None:
    """Render the rich terminal report from a typed ScanResult."""
    console = console or theme.make_console()
    if result.kind == "web":
        console.print(
            Panel(
                _web_summary_text(result.web_findings, result.meta),
                title="Summary",
                border_style=PURPLE,
                title_align="center",
            )
        )
        if result.web_findings:
            console.print(web_findings_table(result.web_findings))
    else:
        meta = result.meta
        console.print(
            Panel(
                f"[bold {ACCENT}]blacklight-cli[/] v{__version__} - scan report\n"
                f"Targets: [bold]{meta.targets}[/] | Hosts scanned: {meta.hosts_scanned} | "
                f"Services found: {meta.services_found} | Findings: {meta.findings_count}",
                title="Summary",
                border_style=PURPLE,
                title_align="center",
            )
        )
    hosts = host_risk_table(result.findings)
    if hosts:
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
        console.print(score_table)
    if result.findings:
        console.print(findings_table(result.findings))
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


def export_report(result: ScanResult, fmt: str, output: Path) -> Path:
    """Write the report in html, markdown, or json format."""
    meta = result.meta
    payload = {
        "meta": asdict(meta),
        "findings": [f.to_dict() for f in result.findings],
        "hosts": host_risk_table(result.findings),
        "web": (
            {"meta": asdict(meta), "findings": [f.to_dict() for f in result.web_findings]}
            if result.kind == "web"
            else None
        ),
    }
    if fmt == "json":
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif fmt == "html":
        output.write_text(
            _load_template("report.html.j2", autoescape=True).render(**payload),
            encoding="utf-8",
        )
    elif fmt == "markdown":
        output.write_text(
            _load_template("report.md.j2").render(**payload),
            encoding="utf-8",
        )
    else:
        raise ValueError(f"Unknown format: {fmt}")
    return output
```

Import `asdict` from `dataclasses` (already imported) and `ScanResult` from `blacklight.engine`. Watch the import cycle: `engine.py` imports `reporter`, and `reporter` would import `engine` — cycle. **Fix: put the imports inside the functions or late-import**:

```python
def render_terminal(result, console=None):
    from blacklight.engine import ScanResult  # no strong typing; local import avoids engine->reporter->engine cycle
```

Better structural fix: define `ScanResult` etc. in a module that both import — simplest for this plan's blast: make `reporter.py` import `ScanResult` from `engine` lazily inside the functions (acceptable), or note the cycle and place the dataclasses in `engine.py` while using `TYPE_CHECKING`-free local imports. The plan picks **local imports inside functions** to avoid restructuring on day 1.

Similarly `engine`'s `render_terminal(result, params.fmt ...)` calls change to the new signatures; and the `_legacy_meta` projection is deleted.

- [ ] **Step 4: run suite**

Run: `python -m pytest -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add blacklight/reporter.py blacklight/engine.py tests/test_reporter.py
git commit -m "feat: reporter consumes typed ScanResult"
```

---

### Task 5: delete `web/engine.py` and slim `cli.py` to a shell

**Files:**
- Delete: `blacklight/web/engine.py`
- Modify: `blacklight/web/__init__.py`
- Modify: `blacklight/cli.py` (delete `execute_scan`/`execute_web`; `scan`/`web`/`console` commands call `engine` directly)
- Modify: `blacklight/console.py` (wire engine)
- Modify: `blacklight/tui/app.py`, `blacklight/tui/views.py` (single injected run)
- Modify: `tests/test_cli.py` (migrate pipeline tests), `tests/test_web_engine.py` (delete/migrate), `tests/view_tui.py`, `tests/test_console.py`

**Interfaces:**
- Consumes: `engine.run`, `engine.NetworkScan`, `engine.WebScan`, `ScanParams`
- Produces: `cli.scan()`, `cli.web()`, `cli._console_command()`; `CommandRunner(run=...)`; `BlacklightApp(run=...)`

- [ ] **Step 1: delete `web/engine.py` and fix `web/__init__.py`**

Delete the file; rewrite `web/__init__.py`:

```python
"""Web application scanning: passive, error-based checks."""
```

- [ ] **Step 2: rewire `cli.py` to drop execute_* wrappers**

The `scan` command:

```python
@app.command()
def scan(
    target: list[str] = typer.Argument(..., help="Target host(s) or CIDR(s)."),
    ports: str = typer.Option("1-1024", "--ports", "-p", help="Port range(s) to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Export report to a file."),
    fmt: str = typer.Option("html", "--format", help="Export format: html, markdown, json."),
    i_have_permission: bool = typer.Option(
        False, "--i-have-permission",
        help="Confirm you are authorized to scan these targets."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the local NVD/EPSS cache."),
    timeout: int = typer.Option(30, "--timeout", help="Per-host nmap scan timeout in seconds."),
) -> None:
    """Scan targets for vulnerable services and report findings."""
    params = ScanParams(permission_granted=i_have_permission, timeout=timeout,
                        no_cache=no_cache, ports=ports, output=output, fmt=fmt)
    raise typer.Exit(code=engine.run(
        engine.NetworkScan(), list(target), params,
        confirm=lambda message: typer.confirm(message),
        console=console,
    ))
```

The `web` command:

```python
@app.command()
def web(
    url: str = typer.Argument(...),
    i_have_permission: bool = ...,
    no_cache: bool = ...,
    output: Path | None = ...,
    fmt: str = ...,
    timeout: int = ...,
) -> None:
    """Scan a web application for misconfigurations and injection flawes."""
    params = ScanParams(permission_granted=i_have_permission, timeout=timeout,
                        no_cache=no_cache, output=output, fmt=fmt)
    raise typer.Exit(code=engine.run(
        engine.WebScan(), [url], params,
        confirm=lambda message: typer.confirm(message),
        console=console,
    ))
```

`console` command:

```python
@app.command("console")
def _console_command() -> None:
    """Start an interactive scan console (same as running 'blacklight' bare)."""
    from blacklight.console import ConsoleApp

    ConsoleApp().run()
```

Delete `execute_scan`, `execute_web`, and the now-unused `history` calls of the top-of-module imports (`from black_light.web.engine import run_web_scan`, `Progress`, etc.). Keep `render_terminal`/`export_report` imports removed too (engine owns them now).

- [ ] **Step 3: rewire `console.py`**

`CommandRunner`:

```python
class CommandRunner:
    """Parses and dispatches one console line at a time.

    Pure by design: the scan/web pipeline and the authorization
    confirm are injected callables, so this class never touches
    typer or the network.
    """

    def __init__(
        self,
        *,
        run: Callable[..., int],
        confirm: Callable[[str], bool] | None = None,
    ) -> None:
        self.run = run
        self.confirm = confirm or (lambda m: False)
        self.state = ConsoleState(modules={"scan": SCAN_MODULE, "web": WEB_MODULE})
```

`_run`:

```python
    def _run(self, args: list[str], console: Console) -> None:
        if args:
            console.print("[red]Usage: run[/]")
            return
        error, targets, kwargs = module_run_args(self.state)
        if error:
            console.print(f"[red]{error}[/]")
            return
        module = self.state.active_module()
        assert module is not None
        kwargs["confirm"] = self.confirm
        code = self.run(module.name, targets, kwargs)
        console.print("[green]Done.[/]" if code == 0
                      else "[red]Done with errors.[/]")
```

Add an engine-facing execute callable in `ConsoleApp`:

```python
    def _engine_run(self, kind: str, targets: list[str], kwargs: dict) -> int:
        executor = engine.NetworkScan() if kind == "scan" else engine.WebScan()
        params = ScanParams(
            permission_granted=kwargs.get("permission_granted", False),
            timeout=kwargs.get("timeout", 30),
            no_cache=kwargs.get("no_cache", False),
            ports=kwargs.get("ports"),
            output=kwargs.get("output"),
            fmt=kwargs.get("fmt", "html"),
        )
        return engine.run(executor, targets, params,
                          confirm=kwargs.get("confirm"),
                          on_progress=kwargs.get("on_progress"))
```

`ConsoleApp.__init__` drops the two callables; construct the runner with `_engine_run`:

```python
    def __init__(self, *, confirm: Callable[[str], bool] | None = None) -> None:
        self._confirm = confirm or self._confirm_plain
        self.runner = CommandRunner(run=self._engine_run, confirm=self._confirm)
```

`_run_interactive` passes `engine-run` to TUI:

```python
    def _run_interactive(self) -> None:
        try:
            from blacklight.tui import app as tui_app

            tui_app.BlacklightApp(run=self._engine_run, confirm=self._confirm).run()
        except Exception:
            theme.make_console(stderr=True).print(
                "[yellow]console: interactive mode unavailable; "
                "pipe commands via stdin instead.[/]"
            )
```

`_confirm_plain` stays. The `_print_header` unchanged.

- [ ] **Step 4: rewire TUI**

`blacklight/tui/app.py`:

```python
class BlacklightApp(App):
    """Full-screen console: modules, options, runs, and history."""

    BINDINGS = [("q", "quit_app", "Quit")]
    TITLE = "blacklight-cli console"
    theme = "tokyo-night"

    def __init__(
        self,
        *,
        run: Callable[..., int],
        confirm: Callable[[str], bool] | None = None,
    ) -> None:
        super().__init__()
        self._run = run
        self._confirm = confirm
        self._bridge = ConfirmBridge(self)
        self.runner: CommandRunner = None  # type: ignore[assignment]

    def on_mount(self) -> None:
        self.runner = CommandRunner(run=self._run, confirm=self._confirm or self._bridge.ask)
        self.push_screen(MainScreen())
```

`blacklight/tui/views.py`:
- `capture_engine_output` swaps `engine.console` instead of `cli.console`:

```python
@contextlib.contextmanager
def capture_engine_output(on_line):
    """Route engine console writes into the TUI instead of stdout."""
    from blacklight import engine

    sink = _CaptureStream(on_line)
    saved = engine.console
    engine.set_console(theme.make_console(file=sink))
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            yield
    finally:
        engine.set_console(saved)
        sink.flush()
```

(Drop the `from blacklight import cli` and the old swap of `cli.console`.)

- `RunScreen._run_task` calls the single `run`:

```python
    def _run_task(self) -> None:
        error, targets, kwargs = module_run_args(self.app.runner.state)
        if error:
            self._set_title("Run failed")
            self._log(f"{error}")
            return
        module = self.app.runner.state.active
        self._set_title(f"Running {module} on {', '.join(targets)}")
        self._log(f"Starting {module} scan of {', '.join(targets)} ...")
        try:
            kwargs["confirm"] = self.app.runner.confirm
            with capture_engine_output(self._log):
                if module == "scan":
                    budget = (kwargs.get("timeout") or 30) * 2 + 120
                    self.app.call_from_thread(self._start_progress, budget)
                    kwargs["on_progress"] = self._on_progress
                    code = self.app.runner.run("scan", targets, kwargs)
                else:
                    self.app.call_from_thread(self._start_progress, 60)
                    code = self.app.runner.run("web", targets, kwargs)
            self._finish_progress()
        except Exception as exc:
            self._log(f"Scan failed: {exc}")
            self._set_title("Run failed")
            self._fail_progress()
            return
        self._log("Done." if code == 0 else "Done with errors.")
        self._show_findings(module, targets[0])
```

(`kwargs["on_progress"]` flows through `_engine_run`/orchestrator; the web path needs no on_progress — orchestrator only calls it if provided. Note `_engine_run` passes the on_progress from kwargs each run.)

- [ ] **Step 5: update tests for the new seams**

`tests/test_console.py`:
- `make_runner` → `make_runner(run=..., confirm=...)` where the fake `run(kind, targets, kwargs)` records `(kind, targets, kwargs)` and returns 0.
- `test_run_invokes_execute_scan_with_converted_options` → `test_run_invokes_run_scan_with_converted_options`: fake `run("scan", targets, kwargs)`; assert `kwargs["timeout"] == 30`, `kwargs["no_cache"] is False`, `kwargs["fmt"] == "html"`, target list.
- `test_run_invokes_execute_web_with_first_target` → kind "web", the run gets `targets[0]`.
- `test_run_forwards_injected_confirm`: assert `kwargs["confirm"] is confirm_cb`.
- `test_console_command_piped_session` `monkeypatch.setattr("black.light.cli.execute_scan", ...)` → set `captured` through the injected runner instead (the piped path goes through `ConsoleApp().run()` → stdin loop; patch `blacklight.console.ConsoleApp` runner? Simplest: monkeypatch the typed seam `engine.run` to a sentinel for the piped test.

`tests/test_tui.py`:
- `make_app` builds `BlacklightApp(verify=..., run=...)`: replace `execute_scan`/`execute_web` params with `run=recording_run`.

`tests/test_engine.py`:
- Migrate the network/web adapter tests from `test_web_engine.py` (now deleted) — the WebScan tests in Step 1 Task 1 already cover adapter behavior. Remove `tests/test_web_engine.py`.

`test_cli_web.py` and `test_cli.py`: engine now owns the seam; the typer-shell tests keep expectations (exit codes, block/abort text). Migrate the deeper `execute_scan`/`run_scan`-shape tests into `test_engine.py` orchestrator tests (already written in Task 2).

- [ ] **Step 6: run the full suite**

Run: `python -m pytest -q`
Expected: PASS. (If any consumer still imports `blacklight.web.engine`, fix the import.)

- [ ] **Step 7: Commit**

```bash
git add blacklight/cli.py blacklight/console.py blacklight/tui blacklight/web blacklight/tui/__init__.py
rm blacklight/web/engine.py tests/test_web_engine.py 2>/dev/null
git add -A
git commit -m "refactor: single injected orchestrator for cli, console, TUI"
```

---

### Task 6: consolidate tests + cleanup

**Files:**
- Modify: `tests/test_engine.py` (final shape), `tests/test_cli.py` (final shape), `CONTEXT.md`
- Possibly remove dead code: `blacklight/reporter.py` no longer needs `meta`/`web_meta` dict branches (already done in Task 4); `engine.py`'s `_legacy_meta` should be gone.

- [ ] **Step 1: sweep for `_legacy_meta` and dict-meta residue**

Run: `grep -rn "_legacy_meta\|render_terminal([]\|record_scan(\"" blacklight tests`
Expected: no matches (or fix any that remain).

- [ ] **Step 2: run the suite + a real smoke scan**

Run: `python -m pytest -q`
Expected: PASS.

Run a quick real invocation for both kinds (private targets):

```bash
python -m blacklight.cli scan 127.0.0.1 -p 1-100 --format json -o /tmp/s.json
python -m blacklight.cli web http://127.0.0.1 -o /tmp/w.md --format markdown
```

Expected: exit 0; history records; files written.

- [ ] **Step 3: update CONTEXT.md**

Ensure the glossary names the seam: **engine.py** module, **executor adapter** (`NetworkScan`/`WebScan`), **ScanResult**, `engine.run`, `confirm`, `on_progress`. If `CONTEXT.md` refers to old kinds ("execut_scan"/`execute_web`), update them.

- [ ] **Step 4: Commit**

```bash
git add CONTEXT.md tests/
git commit -m "chore: final scan-pipeline seam cleanup"
```

---

## Self-Review Notes / Explicitly Out of Scope

- **Progress interface (STAGES re-declaration, budget formula, fake web progress)** — that is candidate #2 and deliberately untouched; `on_progress` remains a callback on `engine.run`. The budget formula duplication (`scanner.timeout*2+120` vs `tui/views.budget`) is also candidate #2.
- **Output seam / global-console capture** — candidate #4; `capture_engine_output` now swaps `engine.console`, same technique as before, just reboused.
- **History store/render split + one risk score** — candidate #3; out of scope except the `record_scan` signature change mandated by Task 3.
- **CPE adapter unification** (candidate #5) and **cache gateway** (candidate #6) — separate plans.
- The `history` diff/trend rendering and `tui` screens keep their current shape; only the injected seam and `record_scan` change.
- If any task's diff grows beyond comfortable review, split it at a step boundary (each step is independently testable).