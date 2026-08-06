"""Screens and modals for the blacklight TUI."""

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Log,
    ProgressBar,
)

from blacklight.console import module_run_args


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
            table.add_row(
                name,
                self.app.runner.state.current_value(name),
                opt.default,
                opt.help,
            )

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


class RunScreen(Screen):
    """Runs the active module in a worker; streams log + findings table."""

    BINDINGS = [("q", "quit_app", "Quit"), ("escape", "back", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Label(id="run-title")
        yield ProgressBar()
        yield Log(id="run-log", highlight=False)
        yield DataTable(id="findings")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(ProgressBar).update(total=None)
        self.query_one("#findings", DataTable).add_columns(
            "HOST", "PORT", "SERVICE", "CVE", "SEVERITY", "EPSS", "KEV"
        )
        self.run_worker(self._run_task, thread=True)

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
            if module == "scan":
                code = self.app.runner.execute_scan(targets, **kwargs)
            else:
                code = self.app.runner.execute_web(targets[0], **kwargs)
        except Exception as exc:
            self._log(f"Scan failed: {exc}")
            self._set_title("Run failed")
            return
        self._log("Done." if code == 0 else "Done with errors.")
        self._show_findings(module, targets[0])

    def _log(self, line: str) -> None:
        self.app.call_from_thread(
            self.query_one("#run-log", Log).write_line, line
        )

    def _set_title(self, title: str) -> None:
        self.app.call_from_thread(
            self.query_one("#run-title", Label).update, title
        )

    def _show_findings(self, kind: str, target: str) -> None:
        def fill() -> None:
            from blacklight import history
            record = history.latest_scan(kind, target)
            log = self.query_one("#run-log", Log)
            if record is None:
                log.write_line("No history entry recorded for this run.")
                return
            table = self.query_one("#findings", DataTable)
            for rec in history.findings_for(record.id):
                table.add_row(
                    rec.host or "",
                    "" if rec.port is None else str(rec.port),
                    rec.service or "",
                    rec.cve_id or "",
                    rec.severity,
                    "" if rec.epss is None else f"{rec.epss:.3f}",
                    "KEV" if rec.in_kev else "",
                )
            log.write_line(f"{len(history.findings_for(record.id))} findings.")

        self.app.call_from_thread(fill)

    def action_back(self) -> None:
        self.app.pop_screen()


class HistoryScreen(Screen):
    """Recent scans; enter shows the diff, t shows the trend."""

    BINDINGS = [
        ("q", "quit_app", "Quit"),
        ("escape", "back", "Back"),
        ("t", "trend", "Trend"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Label("SCAN HISTORY - enter: diff, t: trend")
        yield DataTable(id="history")
        yield Footer()

    def on_mount(self) -> None:
        import sqlite3

        from blacklight import history
        table = self.query_one("#history", DataTable)
        table.cursor_type = "row"
        table.add_columns(
            "ID", "KIND", "TARGET", "HOSTS", "SERVICES", "FINDINGS", "SCANNED AT"
        )
        try:
            rows = history.list_recent()
        except sqlite3.Error as exc:
            table.add_row(f"History database error: {exc}")
            return
        for row in rows:
            table.add_row(
                str(row.id), row.kind, row.target, str(row.hosts),
                str(row.services), str(row.findings_count), row.scanned_at,
            )

    def _selected_target(self) -> str | None:
        table = self.query_one("#history", DataTable)
        if table.row_count == 0:
            return None
        return table.get_row_at(table.cursor_row)[2]

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        target = self._selected_target()
        if target:
            self.app.push_screen(DetailScreen(target=target))

    def action_trend(self) -> None:
        target = self._selected_target()
        if target:
            self.app.push_screen(DetailScreen(target=target, trend=True))

    def action_back(self) -> None:
        self.app.pop_screen()


class DetailScreen(Screen):
    """Diff or risk trend for one target."""

    BINDINGS = [("q", "quit_app", "Quit"), ("escape", "back", "Back")]

    def __init__(self, *, target: str, trend: bool = False) -> None:
        super().__init__()
        self._target = target
        self._trend = trend

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Label(id="detail-title")
        yield DataTable(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        from blacklight import history
        table = self.query_one("#detail", DataTable)
        table.cursor_type = "row"
        title = self.query_one("#detail-title", Label)
        if self._trend:
            title.update(f"RISK TREND - {self._target}")
            table.add_columns("SCANNED AT", "SCORE")
            points = history.trend_for_target(self._target)
            if points is None:
                table.add_row("No scans of this target yet.")
                return
            for point in points:
                table.add_row(point.scanned_at, f"{point.score:.1f}")
            return
        result = history.diff_for_target(self._target)
        title.update(f"DIFF - {self._target}")
        if result is None:
            table.add_row("No previous scan of this target.")
            return
        before = ("?" if result.score_before is None
                  else f"{result.score_before:.1f}")
        title.update(
            f"DIFF - {self._target}  score "
            f"{before} -> {result.score_after:.1f}"
        )
        table.add_columns("STATUS", "HOST", "SERVICE", "CVE", "SEVERITY")
        for rec in result.new:
            table.add_row("NEW", rec.host or "", rec.service or "",
                          rec.cve_id or "", rec.severity)
        for rec in result.fixed:
            table.add_row("FIXED", rec.host or "", rec.service or "",
                          rec.cve_id or "", rec.severity)
        for rec in result.unchanged:
            table.add_row("SAME", rec.host or "", rec.service or "",
                          rec.cve_id or "", rec.severity)

    def action_back(self) -> None:
        self.app.pop_screen()


class ConfirmModal(ModalScreen[bool]):
    """Yes/No modal shown when an engine asks for authorization."""

    BINDINGS = [("escape", "no", "No")]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        yield Label(self._message)
        with Horizontal():
            yield Button("Yes", variant="primary", id="yes")
            yield Button("No", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_no(self) -> None:
        self.dismiss(False)