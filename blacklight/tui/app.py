"""Textual application hosting the blacklight console TUI."""

from collections.abc import Callable

from textual.app import App, ComposeResult

from blacklight.console import CommandRunner

from blacklight.tui.views import MainScreen


class BlacklightApp(App):
    """Full-screen console: modules, options, runs, and history."""

    BINDINGS = [("q", "quit_app", "Quit")]
    TITLE = "blacklight-cli console"

    def __init__(
        self,
        *,
        execute_scan: Callable[..., int],
        execute_web: Callable[..., int],
        confirm: Callable[[str], bool] | None = None,
    ) -> None:
        super().__init__()
        self._execute_scan = execute_scan
        self._execute_web = execute_web
        self._confirm = confirm
        self.runner: CommandRunner = None  # type: ignore[assignment]

    def on_mount(self) -> None:
        self.runner = CommandRunner(
            execute_scan=self._execute_scan,
            execute_web=self._execute_web,
            confirm=self._confirm or (lambda message: True),
        )
        self.push_screen(MainScreen())

    def action_quit_app(self) -> None:
        self.exit(0)