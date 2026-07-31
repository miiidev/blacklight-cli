"""blacklight-cli entry point."""

import typer
from rich.console import Console

from blacklight import __version__

console = Console()

app = typer.Typer(
    help="blacklight-cli: scan networks for vulnerable services. "
    "For use only on systems you own or are authorized to test."
)


@app.callback()
def _noop() -> None:
    """No-op callback: keeps blacklight a command group with subcommands."""
    pass


@app.command()
def version() -> None:
    """Show the installed version."""
    console.print(f"blacklight-cli {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
