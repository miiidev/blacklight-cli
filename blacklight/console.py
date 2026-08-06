"""msfconsole-style interactive session for blacklight-cli."""

import re
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TextIO

from rich.console import Console

from blacklight import __version__, history, paths
from blacklight import theme


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

    def active_module(self) -> Module | None:
        if self.active is None:
            return None
        return self.modules[self.active]

    def current_value(self, name: str) -> str:
        if name in self.values:
            return self.values[name]
        module = self.active_module()
        assert module is not None
        return module.options[name].default


def module_run_args(state: ConsoleState) -> tuple[str | None, list[str], dict]:
    """Validate the active module and build run arguments.

    Returns (error, targets, kwargs); error is None when valid.
    """
    module = state.active_module()
    if module is None:
        return "No module selected.", [], {}
    try:
        timeout = int(state.current_value("TIMEOUT"))
    except ValueError:
        return "TIMEOUT must be an integer.", [], {}
    if timeout <= 0:
        return "TIMEOUT must be a positive integer.", [], {}
    target = state.current_value("TARGET").strip()
    if not target:
        return "TARGET not set.", [], {}
    targets = [t for t in re.split(r"[\s,]+", target) if t]
    output = state.current_value("OUTPUT").strip()
    kwargs = {
        "timeout": timeout,
        "no_cache": state.current_value("NO_CACHE") == "true",
        "output": Path(output) if output else None,
        "fmt": state.current_value("FORMAT"),
        "permission_granted": state.current_value("PERMISSION") == "true",
    }
    if module.name == "scan":
        kwargs["ports"] = state.current_value("PORTS")
    return None, targets, kwargs


HELP_TEXT = """Commands:
  help                 Show this help
  modules              List available modules
  use <module>         Select a module (scan, web)
  show options         Show the active module's options
  set <OPT> <value>    Set an option (e.g. set TARGET 192.168.1.10)
  unset <OPT>          Reset an option to its default
  run                  Run the active module with current options
  back                 Deselect the active module
  history              List recent scans
  history <target>     Diff the latest scan of <target> vs its previous scan
  trend <target>       Show the risk-score trend for <target>
  exit | quit          Leave the console
"""


class CommandRunner:
    """Parses and dispatches one console line at a time.

    Pure by design: the scan/web pipelines and the authorization confirm
    are injected callables, so this class never touches typer or the
    network.
    """

    def __init__(
        self,
        *,
        execute_scan: Callable[..., int],
        execute_web: Callable[..., int],
        confirm: Callable[[str], bool],
    ) -> None:
        self.execute_scan = execute_scan
        self.execute_web = execute_web
        self.confirm = confirm
        self.state = ConsoleState(modules={"scan": SCAN_MODULE, "web": WEB_MODULE})

    # -- dispatch -------------------------------------------------------

    def execute(self, line: str, out: TextIO = sys.stdout) -> bool:
        """Handle one input line. Returns True when the loop should exit."""
        line = line.strip()
        if not line:
            return False
        parts = line.split(None, 2)
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        console = theme.make_console(file=out, highlight=False)

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
        elif cmd == "history":
            self._history(args, console)
        elif cmd == "trend":
            self._trend(args, console)
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
        module = self.state.active_module()
        if module is None:
            console.print("[red]No module selected. Use 'use <module>' first.[/]")
            return
        console.print(f"Module: [bold]{module.name}[/] - {module.description}")
        console.print(f"{'OPTION':<10} {'CURRENT':<16} {'DEFAULT':<16} DESCRIPTION")
        for name, option in module.options.items():
            console.print(f"{name:<10} {self.state.current_value(name):<16} "
                          f"{option.default:<16} {option.help}")

    def _set(self, args: list[str], console: Console) -> None:
        module = self.state.active_module()
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
        module = self.state.active_module()
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
        error, targets, kwargs = module_run_args(self.state)
        if error:
            console.print(f"[red]{error}[/]")
            return
        module = self.state.active_module()
        assert module is not None
        kwargs["confirm"] = self.confirm
        if module.name == "scan":
            code = self.execute_scan(targets, **kwargs)
        else:
            if len(targets) > 1:
                console.print("[yellow]web accepts a single TARGET; "
                              "scanning the first only[/]")
            code = self.execute_web(targets[0], **kwargs)
        console.print("[green]Done.[/]" if code == 0
                      else "[red]Done with errors.[/]")

    def _history(self, args: list[str], console: Console) -> None:
        if not args:
            try:
                rows = history.list_recent()
            except sqlite3.Error as exc:
                console.print(f"[red]History database error:[/] {exc}")
                return
            history.render_list(rows, console)
            return
        if len(args) != 1:
            console.print("[red]Usage: history [<target>][/]")
            return
        try:
            result = history.diff_for_target(args[0])
        except sqlite3.Error as exc:
            console.print(f"[red]History database error:[/] {exc}")
            return
        if result is None:
            console.print(f"[yellow]No scans of {args[0]} yet.[/]")
            return
        history.render_diff(result, console)

    def _trend(self, args: list[str], console: Console) -> None:
        if len(args) != 1:
            console.print("[red]Usage: trend <target>[/]")
            return
        try:
            points = history.trend_for_target(args[0])
        except sqlite3.Error as exc:
            console.print(f"[red]History database error:[/] {exc}")
            return
        if points is None:
            console.print(f"[yellow]No scans of {args[0]} yet.[/]")
            return
        history.render_trend(points, console, target=args[0])


class ConsoleApp:
    """Console session: interactive Textual TUI or piped (plain input)."""

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
        if sys.stdin.isatty():
            self._run_interactive()
        else:
            self._print_header()
            self._run_piped()
        return 0

    def _print_header(self) -> None:
        names = ", ".join(self.runner.state.modules)
        console = theme.make_console()
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
        try:
            from blacklight.tui import app as tui_app

            tui_app.BlacklightApp(
                execute_scan=self.runner.execute_scan,
                execute_web=self.runner.execute_web,
                confirm=self._confirm,
            ).run()
        except Exception:
            theme.make_console(stderr=True).print(
                "[yellow]console: interactive mode unavailable; "
                "pipe commands via stdin instead.[/]"
            )