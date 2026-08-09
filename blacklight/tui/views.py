"""Screens and modals for the blacklight TUI."""

import contextlib

from rich.text import Text
from textual import events
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
    Static,
)

from blacklight import __version__, theme
from blacklight.console import module_run_args


class _CaptureStream:
    """File-like sink that forwards each completed line to a callback."""

    def __init__(self, on_line):
        self._on_line = on_line
        self._pending = ""

    def write(self, text: str) -> int:
        self._pending += text
        while "\n" in self._pending:
            line, self._pending = self._pending.split("\n", 1)
            if line:
                self._on_line(line)
        return len(text)

    def flush(self) -> None:
        if self._pending:
            line, self._pending = self._pending, ""
            if line:
                self._on_line(line)


@contextlib.contextmanager
def capture_engine_output(on_line):
    """Route engine console writes into the TUI instead of stdout.

    The engine prints progress and results through a module-level rich
    Console bound to stdout. Under the TUI that stdout is Textual's
    alternate screen, so every write corrupts the display and forces
    repaints. Swap the shared console (and fresh consoles created per
    call via sys.stdout) for a plain capture that forwards lines to the
    UI thread instead.
    """
    from blacklight import engine, theme

    sink = _CaptureStream(on_line)
    saved = engine.console
    engine.set_console(theme.make_console(file=sink))
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            yield
    finally:
        engine.set_console(saved)
        sink.flush()


class SplashScreen(Screen):
    """Startup landing screen: animated gradient banner; any key dismisses."""

    CSS = f"""
    SplashScreen {{
        align: center middle;
    }}
    #splash-box {{
        width: {theme.BANNER_WIDTH};
        max-width: 100%;
        height: auto;
        align: center middle;
    }}
    #splash-caption {{
        margin-top: 1;
        color: $text-muted;
        text-align: center;
    }}
    #splash-prompt {{
        margin-top: 2;
        color: $text-muted;
        text-align: center;
    }}
    """

    BINDINGS = [("q", "dismiss", "Dismiss")]

    SHIMMER_INTERVAL = 1 / 30
    PHASE_STEP = 1 / 128
    FADE_INTERVAL = 1 / 60
    FADE_MS = 400
    DISMISS_MS = 300

    def compose(self) -> ComposeResult:
        modules = self.app.runner.state.modules
        caption = (
            f"blacklight-cli v{__version__} · {len(modules)} modules loaded "
            f"({', '.join(modules)})"
        )
        with Vertical(id="splash-box"):
            yield Static(theme.gradient_text(theme.BANNER), id="splash-banner")
            yield Label(caption, id="splash-caption")
            yield Label("Press any key to continue", id="splash-prompt")

    def on_mount(self) -> None:
        self._phase = 0.0
        self._dismissing = False
        self._fade_timer = None
        self._banner = self.query_one("#splash-banner", Static)
        self._banner.update(self._banner_renderable())
        self._timer = self.set_interval(self.SHIMMER_INTERVAL, self._tick)
        self.styles.opacity = 0.0
        self._fade(1.0, self.FADE_MS / 1000)

    def _banner_renderable(self):
        if self.size.width >= theme.BANNER_WIDTH:
            return theme.gradient_text(theme.BANNER, phase=self._phase)
        return Text("blacklight-cli", style=theme.ACCENT)

    def _tick(self) -> None:
        self._phase = (self._phase + self.PHASE_STEP) % 1.0
        self._banner.update(self._banner_renderable())

    @staticmethod
    def _ease(t: float) -> float:
        """Ease-in-out cubic; smooths the start/end of a fade vs. linear."""
        return 4 * t * t * t if t < 0.5 else 1 - pow(-2 * t + 2, 3) / 2

    def _fade(self, target: float, duration: float, on_complete=None) -> None:
        """Ramp styles.opacity to ``target`` over ``duration`` seconds.

        Textual 8's ``animate`` cannot touch widget ``opacity`` (read-only
        property), so the fade is stepped with an interval timer instead.
        Runs on its own fast interval (independent of the shimmer's cadence)
        and eases in/out so the ramp doesn't look mechanical.
        """
        if self._fade_timer is not None:
            self._fade_timer.stop()
        start = self.styles.opacity
        total = max(round(duration / self.FADE_INTERVAL), 1)
        done = 0

        def step() -> None:
            nonlocal done
            done += 1
            if done >= total:
                self.styles.opacity = target
                self._fade_timer.stop()
                if on_complete is not None:
                    on_complete()
            else:
                eased = self._ease(done / total)
                self.styles.opacity = start + (target - start) * eased

        self._fade_timer = self.set_interval(self.FADE_INTERVAL, step)

    def action_dismiss(self) -> None:
        self._dismiss()

    def on_key(self, event: events.Key) -> None:
        event.stop()
        self._dismiss()

    def _dismiss(self) -> None:
        if self._dismissing:
            return
        self._dismissing = True
        self._timer.stop()
        self._fade(
            0.0,
            self.DISMISS_MS / 1000,
            on_complete=lambda: self.app.pop_screen(),
        )


class MainScreen(Screen):
    """Module sidebar + options table + footer keybindings."""

    CSS = """
    #sidebar {
        width: 28;
    }
    #options {
        width: 1fr;
    }
    """

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
        self._progress_running = False
        self._budget = 60.0
        self._ticker = self.set_interval(0.5, self._tick_progress, pause=True)
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
            with capture_engine_output(self._log):
                if module == "scan":
                    budget = (kwargs.get("timeout") or 30) * 2 + 120
                    self.app.call_from_thread(self._start_progress, budget)
                    kwargs["on_progress"] = self._on_progress
                    code = self.app.runner.run("scan", targets, kwargs)
                else:
                    self.app.call_from_thread(self._start_progress, 60)
                    code = self.app.runner.run("web", targets[:1], kwargs)
            self._finish_progress()
        except Exception as exc:
            self._log(f"Scan failed: {exc}")
            self._set_title("Run failed")
            self._fail_progress()
            return
        self._log("Done." if code == 0 else "Done with errors.")
        self._show_findings(module, targets[0])

    STAGES = {
        "scanning": "Scanning hosts with nmap",
        "matching": "Matching CVEs against NVD",
        "enriching": "Enriching with EPSS/KEV",
    }

    def _on_progress(self, stage, current, total) -> None:
        self.app.call_from_thread(
            self._show_progress, stage, current, total
        )

    def _tick_progress(self) -> None:
        bar = self.query_one(ProgressBar)
        if not self._progress_running or bar.total is None or bar.total == 1:
            return
        bar.advance(0.5)

    def _start_progress(self, budget: float) -> None:
        self._budget = budget
        self._progress_running = True
        self.query_one(ProgressBar).update(total=budget, progress=0)
        self._ticker.resume()

    def _show_progress(self, stage, current, total) -> None:
        bar = self.query_one(ProgressBar)
        if total:
            self._progress_running = False
            self._ticker.pause()
            bar.update(total=total, progress=current)
        self._set_title_ui(self.STAGES.get(stage, stage))

    def _finish_progress(self) -> None:
        self.app.call_from_thread(self._finish_progress_ui)

    def _finish_progress_ui(self) -> None:
        self._progress_running = False
        self._ticker.pause()
        self.query_one(ProgressBar).update(total=1, progress=1)
        self._set_title_ui(self.app.runner.state.active.title())

    def _fail_progress(self) -> None:
        self.app.call_from_thread(self._fail_progress_ui)

    def _fail_progress_ui(self) -> None:
        self._progress_running = False
        self._ticker.pause()
        self.query_one(ProgressBar).update(total=1, progress=0)

    def _log(self, line: str) -> None:
        self.app.call_from_thread(
            self.query_one("#run-log", Log).write_line, line
        )

    def _set_title(self, title: str) -> None:
        self.app.call_from_thread(self._set_title_ui, title)

    def _set_title_ui(self, title: str) -> None:
        self.query_one("#run-title", Label).update(title)

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

    CSS = """
    ConfirmModal {
        align: center middle;
    }
    #confirm-box {
        width: auto;
        height: auto;
        border: round $border;
        padding: 1 2;
    }
    #confirm-buttons {
        width: auto;
        height: auto;
    }
    """

    BINDINGS = [
        ("escape", "no", "No"),
        ("y", "yes", "Yes"),
        ("n", "no", "No"),
    ]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Label(self._message)
            with Horizontal(id="confirm-buttons"):
                yield Button("Yes", variant="primary", id="yes")
                yield Button("No", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_no(self) -> None:
        self.dismiss(False)

    def action_yes(self) -> None:
        self.dismiss(True)