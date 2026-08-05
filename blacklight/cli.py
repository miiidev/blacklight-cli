"""blacklight-cli entry point: scan command with authorization guardrails."""

import os
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import requests
import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from blacklight import __version__, history, paths
from blacklight import theme
from blacklight import enrichment, guardrails, scanner
from blacklight.cve_matcher import Finding, NvdClient, build_findings
from blacklight.reporter import export_report, render_terminal
from blacklight.web.engine import run_web_scan

# Windows: ensure redirected output (cp1252 pipes) can encode the banner glyphs.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass

console = Console()

app = typer.Typer(
    help="blacklight-cli: scan networks for vulnerable services. "
    "For use only on systems you own or are authorized to test."
)


@app.callback(invoke_without_command=True)
def _entry(ctx: typer.Context) -> None:
    """Show the brand banner, then run the console when no subcommand was given."""
    theme.print_banner(console)
    if ctx.invoked_subcommand is None:
        from blacklight.console import ConsoleApp

        ConsoleApp(execute_scan=execute_scan, execute_web=execute_web).run()


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
    try:
        history.record_scan("scan", ", ".join(sorted(targets)),
                            permission_granted, result["meta"],
                            result["findings"])
    except (OSError, sqlite3.Error) as exc:
        console.print(f"[yellow]Could not record scan history:[/] {exc}")
    render_terminal(result["findings"], result["meta"])
    if output is not None:
        try:
            export_report(result["findings"], result["meta"], fmt, output)
        except (OSError, ValueError) as exc:
            console.print(f"[red]Report export failed:[/] {exc}")
            return 1
        console.print(f"Report written to [bold]{output}[/]")
    return 0


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
    try:
        history.record_scan("web", url, permission_granted,
                            result.meta, result.findings)
    except (OSError, sqlite3.Error) as exc:
        console.print(f"[yellow]Could not record scan history:[/] {exc}")
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


@app.command("console")
def _console_command() -> None:
    """Start an interactive scan console (same as running 'blacklight' bare)."""
    from blacklight.console import ConsoleApp

    ConsoleApp(execute_scan=execute_scan, execute_web=execute_web).run()


@app.command()
def version() -> None:
    """Show the installed version."""
    console.print(f"blacklight-cli {__version__}")


def run_scan(targets: list[str], ports: str, timeout: int, no_cache: bool) -> dict:
    """Run the full pipeline: scan -> CVE match -> enrich -> score metadata."""
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
        progress.add_task("Scanning hosts with nmap...", total=None)
        records = scanner.scan_hosts(targets, ports, timeout)
        phase = progress.add_task("Matching CVEs against NVD...", total=len(records))
        client = NvdClient(api_key=os.environ.get("BLACKLIGHT_NVD_KEY"), no_cache=no_cache)
        findings: list[Finding] = []
        for record in records:
            findings.extend(build_findings([record], client))
            progress.advance(phase)
        progress.add_task("Enriching with EPSS/KEV...", total=None)
        findings = enrichment.enrich_findings(findings)
    hosts_scanned = len({record.host for record in records})
    return {
        "findings": findings,
        "meta": {
            "targets": ", ".join(targets),
            "hosts_scanned": hosts_scanned,
            "services_found": len(records),
            "findings_count": len(findings),
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    }


def _log_scan(targets: list[str], permission: bool, meta: dict) -> None:
    """Append one line per scan to ~/.blacklight/scan.log."""
    line = (
        f"{meta['generated']} target={','.join(targets)} "
        f"permission={permission} hosts={meta['hosts_scanned']} "
        f"services={meta['services_found']} findings={meta['findings_count']}\n"
    )
    with paths.SCAN_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line)


def _log_web_scan(url: str, permission: bool, meta: dict) -> None:
    """Append one line per web scan to ~/.blacklight/scan.log."""
    line = (
        f"{meta['generated']} url={meta['url']} "
        f"permission={permission} checks={meta['checks_run']} "
        f"errors={meta['checks_errored']} findings={meta['cve_findings']}\n"
    )
    with paths.SCAN_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line)


history_app = typer.Typer(help="Scan history, diffs, and risk trends.")


@history_app.callback(invoke_without_command=True)
def _history_entry(ctx: typer.Context) -> None:
    """List recent scans when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        raise typer.Exit(code=_history_list())


@history_app.command()
def diff(
    target: str = typer.Argument(..., help="Target key as stored (hosts or URL)."),
    since: str | None = typer.Option(
        None, "--since",
        help="Diff against the newest scan at/before Nd or YYYY-MM-DD."),
    verbose: bool = typer.Option(
        False, "--verbose", help="List unchanged findings too."),
) -> None:
    """Show what changed between the latest scan of TARGET and its previous scan."""
    raise typer.Exit(code=_history_diff(target, since, verbose))


@history_app.command()
def trend(
    target: str = typer.Argument(..., help="Target key as stored (hosts or URL)."),
    host: str | None = typer.Option(
        None, "--host", help="Filter the trend to one host (network scans)."),
    limit: int = typer.Option(
        50, "--limit", help="Number of recent scans to include."),
) -> None:
    """Show the risk-score history for TARGET, oldest first."""
    raise typer.Exit(code=_history_trend(target, host, limit))


app.add_typer(history_app, name="history")


def _history_list() -> int:
    try:
        rows = history.list_recent()
    except sqlite3.Error as exc:
        console.print(f"[red]History database error:[/] {exc}")
        return 1
    history.render_list(rows, console)
    return 0


def _history_diff(target: str, since: str | None, verbose: bool) -> int:
    try:
        result = history.diff_for_target(target, since=since)
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        console.print("[red]Usage: history diff <target> "
                      "[--since Nd|YYYY-MM-DD] [--verbose][/]")
        return 1
    except sqlite3.Error as exc:
        console.print(f"[red]History database error:[/] {exc}")
        return 1
    if result is None:
        console.print(f"[yellow]No scans of {target} yet.[/]")
        return 0
    history.render_diff(result, console, verbose=verbose)
    return 0


def _history_trend(target: str, host: str | None, limit: int) -> int:
    if limit < 1:
        console.print("[red]LIMIT must be a positive integer.[/]")
        return 1
    try:
        points = history.trend_for_target(target, host=host, limit=limit)
    except sqlite3.Error as exc:
        console.print(f"[red]History database error:[/] {exc}")
        return 1
    if points is None:
        console.print(f"[yellow]No scans of {target} yet.[/]")
        return 0
    history.render_trend(points, console, target=target, host=host)
    return 0


def main() -> None:
    app()


if __name__ == "__main__":
    main()
