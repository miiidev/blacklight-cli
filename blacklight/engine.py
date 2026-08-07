"""One scan pipeline: a typed ScanResult behind two executor adapters.

The orchestrator (engine.run) is the single seam that runs a whole scan:
guardrails verify -> confirm -> scan -> log -> record -> render -> export.
The two genuine variants (network, web) live behind it as adapter objects,
each exposing verify() (guardrails verdict) and run() (a typed ScanResult).
"""

import os
import sqlite3
import subprocess
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from blacklight import enrichment, guardrails, history, paths, scanner, theme
from blacklight.reporter import export_report, render_terminal
from blacklight.cpe_map import service_to_cpe
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
    """Typed outcome of a scan run (shared by history, reporter, and UIs)."""

    kind: str
    target: str
    generated: str
    findings: list[Finding]
    web_findings: list[WebFinding]
    meta: NetworkMeta | WebMeta


class ScanExecutor:
    """Contract for a scan kind: guardrail verification plus a run."""

    kind: str = ""

    def verify(self, targets: list[str], permission_granted: bool) -> Verdict:
        raise NotImplementedError

    def run(
        self,
        targets: list[str],
        params: ScanParams,
        on_progress: Callable[[str, int | None, int | None], None] | None = None,
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
        on_progress: Callable[[str, int | None, int | None], None] | None = None,
    ) -> ScanResult:
        if on_progress:
            on_progress("scanning", None, None)
        with Progress(
            SpinnerColumn(spinner_name="dots", style=theme.ACCENT),
            TextColumn("[cyan]{task.description}"),
            BarColumn(bar_width=None),
        ) as bar:
            bar.add_task("Scanning hosts with nmap...", total=None)
            records = scanner.scan_hosts(targets, params.ports or "1-1024", params.timeout)
            phase = bar.add_task("Matching CVEs against NVD...", total=len(records))
            client = NvdClient(
                api_key=os.environ.get("BLACKLIGHT_NVD_KEY"),
                no_cache=params.no_cache,
            )
            findings: list[Finding] = []
            if on_progress:
                on_progress("matching", 0, len(records))
            for index, record in enumerate(records):
                findings.extend(build_findings([record], client))
                bar.advance(phase)
                if on_progress:
                    on_progress("matching", index + 1, len(records))
            bar.add_task("Enriching with EPSS/KEV...", total=None)
            if on_progress:
                on_progress("enriching", None, None)
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
    """Adapter for web scanning: checks + fingerprint -> CVE -> enrich."""

    kind = "web"

    def verify(self, targets: list[str], permission_granted: bool) -> Verdict:
        url = guardrails.normalize_web_url(targets[0])
        return guardrails.verify_web_target(url, permission_granted)

    def run(
        self,
        targets: list[str],
        params: ScanParams,
        on_progress: Callable[[str, int | None, int | None], None] | None = None,
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
        from blacklight.scanner import ScanRecord

        matched: list[Finding] = []
        for fp in fingerprints:
            cpe = service_to_cpe(fp.service, fp.version)
            if cpe is None:
                continue
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


console = theme.make_console()


def set_console(c: Console) -> None:
    """Point the engine's shared console (TUI capture / --color swap it)."""
    global console
    console = c


def _log_result(kind: str, result: ScanResult, permission: bool) -> None:
    """Append one scan.log line per run; the format differs by kind."""
    meta = result.meta
    if kind == "scan":
        line = (
            f"{result.generated} target={result.target} permission={permission} "
            f"hosts={meta.hosts_scanned} services={meta.services_found} "
            f"findings={meta.findings_count}\n"
        )
    else:
        line = (
            f"{meta.generated} url={result.target} permission={permission} "
            f"checks={meta.checks_run} errors={meta.checks_errored} "
            f"findings={meta.cve_findings}\n"
        )
    with paths.SCAN_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line)


def run(
    executor: ScanExecutor,
    targets: list[str],
    params: ScanParams,
    *,
    confirm: Callable[[str], bool],
    on_progress: Callable[[str, int | None, int | None], None] | None = None,
    console: Console | None = None,
) -> int:
    """Run one scan end-to-end and return the process exit code (0 or 1)."""
    console = console or globals()["console"]
    paths.ensure_dirs()
    verdict = executor.verify(targets, params.permission_granted)
    for blocked in verdict.blocked:
        if executor.kind == "web":
            console.print(f"[red]Blocked:[/] {blocked} must be an http(s) URL for a private "
                          "host, or pass --i-have-permission for public hosts.")
        else:
            console.print(f"[red]Blocked:[/] {blocked} is not a private address. "
                          "Pass --i-have-permission to allow scanning non-private targets.")
    if verdict.needs_confirmation:
        if executor.kind == "web":
            prompt = (f"Target {verdict.needs_confirmation[0]} is public. "
                      "Are you authorized to scan it?")
        else:
            names = ", ".join(verdict.needs_confirmation)
            prompt = f"Target(s) {names} are public. Are you authorized to scan them?"
        if not confirm(prompt):
            console.print("[yellow]Aborted.[/]")
            return 1
    scannable = verdict.allowed + verdict.needs_confirmation
    if not scannable:
        console.print("[red]No scannable targets.[/]")
        return 1
    if executor.kind == "scan" and scanner.find_nmap() is None:
        console.print("[red]nmap not found.[/] Install it with one of:\n"
                      "  apt:   sudo apt install nmap\n"
                      "  brew:  brew install nmap\n"
                      "  choco: choco install nmap")
        return 1
    if params.fmt not in ("html", "markdown", "json"):
        console.print("[red]Invalid format.[/] Choose html, markdown, or json.")
        return 1
    if params.output is not None and params.fmt == "html" \
            and params.output.suffix in (".md", ".json"):
        params.fmt = "markdown" if params.output.suffix == ".md" else "json"

    try:
        result = executor.run(scannable, params, on_progress)
    except (requests.RequestException, subprocess.TimeoutExpired, OSError,
            RuntimeError, ValueError) as exc:
        label = "Web scan" if executor.kind == "web" else "Scan"
        console.print(f"[red]{label} failed:[/] {exc}")
        return 1
    _log_result(executor.kind, result, params.permission_granted)
    try:
        history.record_scan(result, params.permission_granted)
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
