"""blacklight-cli entry point: scan command with authorization guardrails."""

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from blacklight import __version__, paths
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


@app.callback()
def _show_banner() -> None:
    """Show the brand banner before every subcommand invocation."""
    theme.print_banner(console)


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
    paths.ensure_dirs()
    verdict = guardrails.verify_targets(list(target), i_have_permission)
    for blocked in verdict.blocked:
        console.print(f"[red]Blocked:[/] {blocked} is not a private address. "
                      "Pass --i-have-permission to allow scanning non-private targets.")
    if verdict.needs_confirmation:
        names = ", ".join(verdict.needs_confirmation)
        if not typer.confirm(f"Target(s) {names} are public. "
                             "Are you authorized to scan them?"):
            console.print("[yellow]Aborted.[/]")
            raise typer.Exit(code=1)
    targets = verdict.allowed + verdict.needs_confirmation
    if not targets:
        console.print("[red]No scannable targets.[/]")
        raise typer.Exit(code=1)
    if scanner.find_nmap() is None:
        console.print("[red]nmap not found.[/] Install it with one of:\n"
                      "  apt:   sudo apt install nmap\n"
                      "  brew:  brew install nmap\n"
                      "  choco: choco install nmap")
        raise typer.Exit(code=1)
    if fmt not in ("html", "markdown", "json"):
        console.print("[red]Invalid format.[/] Choose html, markdown, or json.")
        raise typer.Exit(code=1)
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
        raise typer.Exit(code=1)
    _log_scan(targets, i_have_permission, result["meta"])
    render_terminal(result["findings"], result["meta"])
    if output is not None:
        try:
            export_report(result["findings"], result["meta"], fmt, output)
        except (OSError, ValueError) as exc:
            console.print(f"[red]Report export failed:[/] {exc}")
            raise typer.Exit(code=1)
        console.print(f"Report written to [bold]{output}[/]")


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
    paths.ensure_dirs()
    url = guardrails.normalize_web_url(url)
    verdict = guardrails.verify_web_target(url, i_have_permission)
    for blocked in verdict.blocked:
        console.print(f"[red]Blocked:[/] {blocked} must be an http(s) URL for a private "
                      "host, or pass --i-have-permission for public hosts.")
    if verdict.needs_confirmation:
        if not typer.confirm(f"Target {url} is public. Are you authorized to scan it?"):
            console.print("[yellow]Aborted.[/]")
            raise typer.Exit(code=1)
    if not (verdict.allowed or verdict.needs_confirmation):
        console.print("[red]No scannable targets.[/]")
        raise typer.Exit(code=1)
    if fmt not in ("html", "markdown", "json"):
        console.print("[red]Invalid format.[/] Choose html, markdown, or json.")
        raise typer.Exit(code=1)
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
        raise typer.Exit(code=1)
    _log_web_scan(url, i_have_permission, result.meta)
    render_terminal([], {}, web_findings=result.findings, web_meta=result.meta)
    if output is not None:
        try:
            export_report([], {}, fmt, output,
                          web_findings=result.findings, web_meta=result.meta)
        except (OSError, ValueError) as exc:
            console.print(f"[red]Report export failed:[/] {exc}")
            raise typer.Exit(code=1)
        console.print(f"Report written to [bold]{output}[/]")


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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
