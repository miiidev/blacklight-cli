"""blacklight-cli entry point: scan command with authorization guardrails."""

import sqlite3
import sys
from pathlib import Path

import typer

from blacklight import __version__, engine, history
from blacklight import theme
from blacklight.engine import ScanParams

# Windows: ensure redirected output (cp1252 pipes) can encode the banner glyphs.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass

# Windows: make the console process ANSI color escapes instead of printing
# them literally (cmd.exe/PowerShell need Virtual Terminal Processing on).
# Applies only when the user opts into colored output via --color.
theme.enable_windows_vt()

# Plain output is the default so blacklight never prints raw ANSI escapes on
# a display that cannot render them; pass --color for the full experience.
console = theme.make_console()

app = typer.Typer(
    help="blacklight-cli: scan networks for vulnerable services. "
    "For use only on systems you own or are authorized to test."
)


@app.callback(invoke_without_command=True)
def _entry(
    ctx: typer.Context,
    color: bool = typer.Option(
        False, "--color", is_eager=True,
        help="Enable colors and animated progress (emits ANSI escapes)."),
) -> None:
    """Show the brand banner, then the help when no subcommand was given."""
    if color:
        global console
        console = theme.make_console(color=True)
    theme.print_banner(console)
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


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
    params = ScanParams(permission_granted=i_have_permission, timeout=timeout,
                        no_cache=no_cache, ports=ports, output=output, fmt=fmt)
    raise typer.Exit(code=engine.run(
        engine.NetworkScan(), list(target), params,
        confirm=lambda message: typer.confirm(message),
        console=console,
    ))


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
    params = ScanParams(permission_granted=i_have_permission, timeout=timeout,
                        no_cache=no_cache, output=output, fmt=fmt)
    raise typer.Exit(code=engine.run(
        engine.WebScan(), [url], params,
        confirm=lambda message: typer.confirm(message),
        console=console,
    ))


@app.command("console")
def _console_command() -> None:
    """Start an interactive scan console (same as running 'blacklight' bare)."""
    from blacklight.console import ConsoleApp

    ConsoleApp().run()


@app.command()
def version() -> None:
    """Show the installed version."""
    console.print(f"blacklight-cli {__version__}")


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
