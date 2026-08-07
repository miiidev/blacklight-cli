"""Textual application hosting the blacklight console TUI."""

import threading
from collections.abc import Callable

from textual.app import App, ComposeResult

from blacklight.console import CommandRunner

from blacklight.tui.views import ConfirmModal, MainScreen


class ConfirmBridge:
    """Routes engine confirm() calls to a modal on the UI thread."""

    def __init__(self, app: "BlacklightApp") -> None:
        self._app = app
        self._event = threading.Event()
        self._answer = False

    def ask(self, message: str) -> bool:
        self._event.clear()
        self._app.call_from_thread(
            self._app.push_screen, ConfirmModal(message), self._answered
        )
        while not self._event.wait(0.1):
            if not self._app.is_running:
                return False
        return self._answer

    def _answered(self, value: bool | None) -> None:
        self._answer = bool(value)
        self._event.set()


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
        self.runner = CommandRunner(
            run=self._run,
            confirm=self._confirm or self._bridge.ask,
        )
        self.push_screen(MainScreen())

    def action_quit_app(self) -> None:
        self.exit(0)