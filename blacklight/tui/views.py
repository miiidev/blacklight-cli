"""Screens and modals for the blacklight TUI."""

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, ListItem, ListView


class MainScreen(Screen):
    """Module sidebar + options table + footer keybindings."""

    BINDINGS = [
        ("q", "quit_app", "Quit"),
        ("r", "run", "Run"),
        ("h", "history", "History"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label("MODULES")
                yield ListView(
                    *[ListItem(Label(name), id=name)
                      for name in self.app.runner.state.modules]
                )
            yield DataTable(id="options")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#options", DataTable)
        table.cursor_type = "row"
        table.add_columns("OPTION", "CURRENT", "DEFAULT", "DESCRIPTION")
        self.refresh_options()
        self.query_one(ListView).focus()

    def refresh_options(self) -> None:
        table = self.query_one("#options", DataTable)
        table.clear()
        module = self.app.runner.state.modules.get(
            self.app.runner.state.active or ""
        )
        if module is None:
            return
        for name, opt in module.options.items():
            value = self.app.runner.state.values.get(name, opt.default)
            table.add_row(name, value, opt.default, opt.help)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.item is None:
            return
        name = event.item.id or ""
        self.app.runner.state.active = name
        self.refresh_options()
        self.query_one("#options", DataTable).focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        module = self.app.runner.state.modules.get(
            self.app.runner.state.active or ""
        )
        if module is None:
            return
        name = list(module.options)[event.cursor_row]
        self.app.push_screen(EditScreen(option=name), self._edit_done)

    def _edit_done(self, value: str | None) -> None:
        module = self.app.runner.state.modules.get(
            self.app.runner.state.active or ""
        )
        if module is None or value is None:
            return
        # The option being edited is the row the cursor is on when the
        # callback fires (EditScreen already popped).
        row = self.query_one("#options", DataTable).cursor_row
        name = list(module.options)[row]
        self.app.runner.state.values[name] = value
        self.refresh_options()

    def action_run(self) -> None:
        if not self.app.runner.state.active:
            self.notify("Select a module first", severity="warning")
            return
        from blacklight.tui.views import RunScreen
        self.app.push_screen(RunScreen())

    def action_history(self) -> None:
        from blacklight.tui.views import HistoryScreen
        self.app.push_screen(HistoryScreen())


class EditScreen(ModalScreen[str]):
    """One-line input to set an option value. Enter submits, esc cancels."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, option: str) -> None:
        super().__init__()
        self.option = option

    def compose(self) -> ComposeResult:
        yield Label(f"{self.option} =")
        yield Input(placeholder="new value")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)