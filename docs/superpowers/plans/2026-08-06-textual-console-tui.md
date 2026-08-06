# Textual Console TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the prompt_toolkit REPL of `blacklight console` with a full-screen Textual TUI (modules, options, live run, findings, history), keeping the piped console path and all engines untouched.

**Architecture:** A new `blacklight/tui/` package holds the Textual `App` (`BlacklightApp`), its screens (`MainScreen`, `RunScreen`, `HistoryScreen`, `DetailScreen`, `EditScreen`, `ConfirmModal`), and a `ConfirmBridge` that marshals engine `confirm()` calls from a worker thread to a UI modal. `BlacklightApp` takes the same injected callables as `ConsoleApp` (`execute_scan`, `execute_web`, `confirm`) and builds a `CommandRunner` from them; a shared `module_run_args(state)` function (extracted from `CommandRunner._run`) supplies run arguments to both the REPL and the TUI. Scan execution runs in a Textual thread worker; findings come from `history.latest_scan()` / `history.findings_for()` after the run (engines return only an exit code). Gate: a throwaway spike app must render in the user's terminal before any TUI code is kept.

**Tech Stack:** Python 3.11+, `textual>=2.0` (new required dependency), existing `rich`/`typer`, Textual `App.run_test()` pilot harness for tests (plain `asyncio.run`, no new dev deps).

## Global Constraints

- `textual>=2.0` added to `pyproject.toml` `[project] dependencies`; `prompt_toolkit>=3` removed from it.
- Engines untouched: `scanner.py`, `cve_matcher.py`, `enrichment.py`, `guardrails.py`, `reporter.py`, `web/*`, `scoring.py`, `paths.py` (except deleting the unused `CONSOLE_HISTORY`), and `history.py`'s storage layer.
- CLI commands `scan`, `web`, `history`, `version` untouched; plain-by-default non-TUI output (`theme.make_console`) preserved.
- Piped console path unchanged: `CommandRunner.execute()` and `ConsoleApp._run_piped()` are not modified.
- Spike gate: if `spike_tui.py` shows garbled output or a blank screen in the user's terminal, stop — the TUI is void (design spec §2, §10).
- TUI tests must not require a real terminal: use `App.run_test()` pilots.
- Commit after every task; run the full suite (`python -m pytest -q`) at each task's end.

---

### Task 1: Spike gate (manual)

**Files:**
- Create: `spike_tui.py` (repo root, deleted after the gate)

**Interfaces:**
- Consumes: nothing
- Produces: a rendered-OK verdict; nothing else depends on this file

- [ ] **Step 1: Install textual**

Run: `python -m pip install "textual>=2.0"`
Expected: installs cleanly.

- [ ] **Step 2: Write the spike app**

`spike_tui.py`:

```python
"""Spike: minimal Textual app gating the TUI effort.

Run: python spike_tui.py
Expected: a header bar, two list rows, a small table, and an
animated progress bar. If this shows raw escape garbage or a blank
screen, the TUI is not viable on this display.
"""

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Label, ProgressBar


class SpikeApp(App):
    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal():
            with Vertical():
                yield Label("MODULES")
                yield Label("scan")
                yield Label("web")
            yield DataTable()
        yield ProgressBar()
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("OPTION", "CURRENT", "DEFAULT")
        table.add_row("TARGET", "", "192.168.1.0/24")
        table.add_row("PORTS", "1-1024", "1-1024")
        self.query_one(ProgressBar).update(total=None)

    def action_quit(self) -> None:
        self.exit(0)


if __name__ == "__main__":
    SpikeApp().run()
```

- [ ] **Step 3: User runs the spike in their terminal**

Run: `python spike_tui.py` in the user's VS Code terminal.
Expected: header bar renders, "scan"/"web" labels visible, table shows two rows, progress bar animates, `q` exits.

**GATE:** If the user reports a garbled or blank screen, STOP here — tell the user the TUI is not viable on their display and the plain console stays. Do not proceed to Task 2.

- [ ] **Step 4: Delete the spike**

```bash
git rm spike_tui.py
```

- [ ] **Step 5: Commit**

```bash
git commit -m "chore: TUI spike passed on user terminal (gate)"
```

---

### Task 2: TUI app shell and wiring

**Files:**
- Create: `blacklight/tui/__init__.py`
- Create: `blacklight/tui/app.py`
- Create: `blacklight/tui/views.py`
- Modify: `blacklight/console.py:291-361` (`ConsoleApp.run`, `_run_interactive`, delete `_prompt_html`)
- Modify: `pyproject.toml:13-19` (dependencies list)
- Test: `tests/test_tui.py` (new)

**Interfaces:**
- Consumes: `CommandRunner` from `blacklight.console` (`CommandRunner(state, execute_scan, execute_web, confirm)`; `runner.state` is a `ConsoleState` with `modules: dict[str, Module]`, `active: str | None`, `values: dict[str, str]`); `theme.make_console` for the piped header.
- Produces: `BlacklightApp(*, execute_scan: Callable[..., int], execute_web: Callable[..., int], confirm: Callable[[str], bool] | None = None)` in `blacklight.tui.app` with attribute `runner: CommandRunner`, method `run()` (Textual `App.run`). Screens: `MainScreen`, `EditScreen(option: str) -> ModalScreen[str]` in `blacklight.tui.views`. Task 3 adds `RunScreen`, `ConfirmModal`, `ConfirmBridge`; Task 4 adds `HistoryScreen`, `DetailScreen`.

- [ ] **Step 1: Write the failing tests**

`tests/test_tui.py`:

```python
import asyncio

import pytest

from blacklight.tui.app import BlacklightApp


def fake_scan(targets, **kwargs):
    return 0


def fake_web(url, **kwargs):
    return 0


def make_app(**kw):
    return BlacklightApp(
        execute_scan=kw.get("execute_scan", fake_scan),
        execute_web=kw.get("execute_web", fake_web),
        confirm=kw.get("confirm", lambda message: True),
    )


def test_tui_launches_and_quits():
    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.runner is not None
            await pilot.press("q")

    asyncio.run(scenario())


def test_tui_lists_modules_and_activates_scan():
    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            from textual.widgets import DataTable
            table = app.query_one("#options", DataTable)
            assert table.row_count == 0
            await pilot.press("enter")  # select first module (scan)
            await pilot.pause()
            assert app.runner.state.active == "scan"
            assert table.row_count == 7  # scan module options
            await pilot.press("q")

    asyncio.run(scenario())


def test_tui_edits_option_value():
    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("enter")  # activate scan
            await pilot.pause()
            from textual.widgets import DataTable
            table = app.query_one("#options", DataTable)
            table.move_cursor(row=0, column=0)  # TARGET row
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press(*"192.168.1.10", "enter")
            await pilot.pause()
            assert app.runner.state.values["TARGET"] == "192.168.1.10"
            await pilot.press("q")

    asyncio.run(scenario())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tui.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.tui'`

- [ ] **Step 3: Add textual to dependencies**

`pyproject.toml` dependencies list becomes:

```toml
dependencies = [
    "typer>=0.12",
    "rich>=13.7",
    "jinja2>=3.1",
    "requests>=2.31",
    "textual>=2.0",
]
```

(Remove `"prompt_toolkit>=3"` only in Task 5 — keep it here until the REPL code is gone, to keep the env installable for tests that still import it.)

- [ ] **Step 4: Create the package and app**

`blacklight/tui/__init__.py`:

```python
"""Full-screen Textual interface for the blacklight console."""
```

`blacklight/tui/app.py`:

```python
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
```


`blacklight/tui/views.py`:

```python
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
```

Note: `RunScreen` and `HistoryScreen` are referenced in `action_run`/`action_history` via local imports; they are created in Tasks 3 and 4. Until then the imports raise `ImportError` at runtime only when the keys are pressed (tests in this task do not press `r` or `h`).

- [ ] **Step 5: Route the interactive console through the TUI**

In `blacklight/console.py`, replace the `ConsoleApp.run` method and delete `_prompt_html`:

```python
    def run(self) -> int:
        paths.ensure_dirs()
        if sys.stdin.isatty():
            self._run_interactive()
        else:
            self._print_header()
            self._run_piped()
        return 0
```

Replace the body of `_run_interactive` (delete the prompt_toolkit imports, the `words`/`session` block, `patch_stdout`, the loop, and `print()`) with:

```python
    def _run_interactive(self) -> None:
        from blacklight.tui.app import BlacklightApp

        BlacklightApp(
            execute_scan=self.runner._execute_scan,
            execute_web=self.runner._execute_web,
            confirm=self._confirm,
        ).run()
```

Delete `_prompt_html` entirely. (Task 3 renames `_execute_scan`/`_execute_web` to public attributes and updates this call site.)

- [ ] **Step 6: Run the new tests**

Run: `python -m pytest tests/test_tui.py -v`
Expected: 3 PASS.

- [ ] **Step 7: Run the full suite**

Run: `python -m pytest -q`
Expected: the three `_run_interactive`/`_prompt_html` tests fail or error (two launch the real Textual app in a non-tty pytest capture, one calls the deleted `_prompt_html`). All other tests pass. Confirm the failures are exactly:
- `test_run_interactive_ends_on_exit`
- `test_run_interactive_survives_keyboard_interrupt`
- `test_prompt_html_reflects_active_module`

These are replaced in Task 5. If more tests fail, stop and diagnose before committing.

- [ ] **Step 8: Commit**

```bash
git add blacklight/tui/ blacklight/console.py pyproject.toml tests/test_tui.py
git commit -m "feat: Textual TUI shell for blacklight console"
```

---

### Task 3: Shared run args, RunScreen, and confirm bridge

**Files:**
- Modify: `blacklight/console.py` — promote `CommandRunner._active`/`_current_value`/`_execute_scan`/`_execute_web`/`_confirm` to public; add module-level `module_run_args(state)`; rewrite `CommandRunner._run` to use it
- Modify: `blacklight/tui/app.py` — add `ConfirmBridge`, `ConfirmModal` import, `Callable` import
- Modify: `blacklight/tui/views.py` — add `RunScreen`; update MainScreen option display to `runner.current_value`
- Test: `tests/test_console.py` (add `module_run_args` tests), `tests/test_tui.py` (add run-pilot test + bridge unit test)

**Interfaces:**
- Consumes: `ConsoleState` (`modules`, `active`, `values`); `history.latest_scan(kind, target) -> ScanRecord | None` (`ScanRecord.id`, `.target`, `.kind`); `history.findings_for(scan_id) -> list[FindingRecord]` (`FindingRecord.host`, `.port`, `.service`, `.cve_id`, `.severity`, `.epss`, `.in_kev`); `CommandRunner.state`, `CommandRunner.execute_scan`/`execute_web`/`confirm` (public after this task).
- Produces: `module_run_args(state: ConsoleState) -> tuple[str | None, list[str], dict]` in `blacklight.console`; `RunScreen` in `blacklight.tui.views` (compose-only screen; `esc` pops, `q` quits); `ConfirmBridge(app)` in `blacklight.tui.app` with `ask(message: str) -> bool`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_console.py`:

```python
def test_module_run_args_validation_errors():
    from blacklight.console import ConsoleState, module_run_args, SCAN_MODULE

    state = ConsoleState(modules={"scan": SCAN_MODULE})
    error, targets, kwargs = module_run_args(state)
    assert error == "No module selected."
    state.active = "scan"
    error, _, _ = module_run_args(state)
    assert error == "TARGET not set."
    state.values["TARGET"] = "192.168.1.10"
    state.values["TIMEOUT"] = "abc"
    error, _, _ = module_run_args(state)
    assert error == "TIMEOUT must be an integer."
    state.values["TIMEOUT"] = "0"
    error, _, _ = module_run_args(state)
    assert error == "TIMEOUT must be a positive integer."


def test_module_run_args_builds_scan_kwargs():
    from blacklight.console import ConsoleState, module_run_args, SCAN_MODULE

    state = ConsoleState(modules={"scan": SCAN_MODULE})
    state.active = "scan"
    state.values["TARGET"] = "192.168.1.10, 192.168.1.11"
    state.values["PERMISSION"] = "true"
    state.values["NO_CACHE"] = "true"
    error, targets, kwargs = module_run_args(state)
    assert error is None
    assert targets == ["192.168.1.10", "192.168.1.11"]
    assert kwargs["timeout"] == 30
    assert kwargs["no_cache"] is True
    assert kwargs["permission_granted"] is True
    assert kwargs["fmt"] == "html"
    assert kwargs["ports"] == "1-1024"
```

Append to `tests/test_tui.py`:

```python
def test_tui_run_invokes_execute_scan_with_args():
    calls = []

    def recording_scan(targets, **kwargs):
        calls.append((targets, kwargs))
        return 0

    app = make_app(execute_scan=recording_scan)

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("enter")  # activate scan
            await pilot.pause()
            from textual.widgets import DataTable
            table = app.query_one("#options", DataTable)
            table.move_cursor(row=0, column=0)
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press(*"192.168.1.10", "enter")
            await pilot.pause()
            await pilot.press("r")
            await pilot.pause()
            await pilot.pause()
            assert len(calls) == 1
            assert calls[0][0] == ["192.168.1.10"]
            assert calls[0][1]["timeout"] == 30
            await pilot.press("q")

    asyncio.run(scenario())


def test_confirm_bridge_blocks_until_answered():
    import threading

    from blacklight.tui.app import ConfirmBridge

    class FakeApp:
        def __init__(self):
            self.modal = None

        def call_from_thread(self, fn, *args, **kwargs):
            fn(*args, **kwargs)

        def push_screen(self, screen, callback):
            self.modal = screen
            callback(True)

    bridge = ConfirmBridge(FakeApp())
    result = []

    def asker():
        result.append(bridge.ask("authorized?"))

    thread = threading.Thread(target=asker)
    thread.start()
    thread.join(timeout=2)
    assert result == [True]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_console.py::test_module_run_args_validation_errors tests/test_console.py::test_module_run_args_builds_scan_kwargs tests/test_tui.py::test_tui_run_invokes_execute_scan_with_args tests/test_tui.py::test_confirm_bridge_blocks_until_answered -v`
Expected: FAIL — `module_run_args` undefined, `ConfirmBridge` undefined, `RunScreen` missing.

- [ ] **Step 3: Promote CommandRunner helpers and add module_run_args**

In `blacklight/console.py`:

1. Rename in `CommandRunner.__init__`: `self._execute_scan` → `self.execute_scan`, `self._execute_web` → `self.execute_web`, `self._confirm` → `self.confirm`. Update the three references inside `_run` (`self._confirm` → `self.confirm`) and `_use`/`_show`/`_set`/`_unset` (references to `self._active()` / `self._current_value` become `self.state.active_module()` / `self.state.current_value(...)`).

2. Add methods to `ConsoleState` (move the logic from `CommandRunner._active`/`_current_value`):

```python
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
```

Delete `CommandRunner._active` and `CommandRunner._current_value`.

3. Add the module-level function after `ConsoleState`:

```python
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
```

4. Rewrite `CommandRunner._run` to use the shared function (its first lines become):

```python
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
        if module.name == "scan":
            code = self.execute_scan(targets, **kwargs)
        else:
            if len(targets) > 1:
                console.print("[yellow]web accepts a single TARGET; "
                              "scanning the first only[/]")
            code = self.execute_web(targets[0], **kwargs)
        console.print("[green]Done.[/]" if code == 0 else "[red]Done with errors.[/]")
```

- [ ] **Step 4: Update Task 2 call sites**

In `blacklight/console.py` `_run_interactive`, replace `self.runner._execute_scan` with `self.runner.execute_scan` and `self.runner._execute_web` with `self.runner.execute_web`.

In `blacklight/tui/views.py` `MainScreen.refresh_options`, replace the value lookup with `self.app.runner.state.current_value(name)`:

```python
        for name, opt in module.options.items():
            table.add_row(
                name,
                self.app.runner.state.current_value(name),
                opt.default,
                opt.help,
            )
```

- [ ] **Step 5: Add ConfirmBridge to app.py**

In `blacklight/tui/app.py`, add `import threading` and `from collections.abc import Callable` to the imports, then:

```python
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
        self._event.wait()
        return self._answer

    def _answered(self, value: bool | None) -> None:
        self._answer = bool(value)
        self._event.set()
```

Change `BlacklightApp.__init__` to build the bridge and pass `confirm` to the runner:

```python
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
        self._bridge = ConfirmBridge(self)
        self.runner: CommandRunner = None  # type: ignore[assignment]

    def on_mount(self) -> None:
        self.runner = CommandRunner(
            execute_scan=self._execute_scan,
            execute_web=self._execute_web,
            confirm=self._confirm or self._bridge.ask,
        )
        self.push_screen(MainScreen())
```

- [ ] **Step 6: Add RunScreen and ConfirmModal to views.py**

Add to imports in `blacklight/tui/views.py`:

```python
from textual.widgets import Button, Log, ProgressBar
```

Append:

```python
class RunScreen(Screen):
    """Runs the active module in a worker; streams log + findings table."""

    BINDINGS = [("q", "quit_app", "Quit"), ("escape", "back", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Label(id="run-title")
        yield ProgressBar()
        yield Log(id="run-log", highlight=False, wrap=True)
        yield DataTable(id="findings")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(ProgressBar).update(total=None)
        self.query_one("#findings", DataTable).add_columns(
            "HOST", "PORT", "SERVICE", "CVE", "SEVERITY", "EPSS", "KEV"
        )
        self.run_worker(self._task, thread=True)

    def _task(self) -> None:
        error, targets, kwargs = module_run_args(self.app.runner.state)
        if error:
            self._set_title("Run failed")
            self._log(f"{error}")
            return
        module = self.app.runner.state.active
        self._set_title(f"Running {module} on {', '.join(targets)}")
        self._log(f"Starting {module} scan of {', '.join(targets)} ...")
        try:
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
```

Add to `views.py` imports: `from blacklight.console import module_run_args`.

- [ ] **Step 7: Run the new tests**

Run: `python -m pytest tests/test_console.py::test_module_run_args_validation_errors tests/test_console.py::test_module_run_args_builds_scan_kwargs tests/test_tui.py::test_tui_run_invokes_execute_scan_with_args tests/test_tui.py::test_confirm_bridge_blocks_until_answered -v`
Expected: 4 PASS.

- [ ] **Step 8: Run the full suite**

Run: `python -m pytest -q`
Expected: only the same three prompt_toolkit/`_prompt_html` tests fail or error. Note: `tests/test_console.py` may exercise `CommandRunner._run` heavily — all of those must still pass after the refactor. If any fail, fix the refactor before committing.

- [ ] **Step 9: Commit**

```bash
git add blacklight/console.py blacklight/tui/ tests/test_console.py tests/test_tui.py
git commit -m "feat: TUI run screen with worker and confirm bridge"
```

---

### Task 4: History screens

**Files:**
- Modify: `blacklight/tui/views.py` — add `HistoryScreen`, `DetailScreen`
- Test: `tests/test_tui.py` (add history pilot tests)

**Interfaces:**
- Consumes: `history.list_recent(limit=20) -> list[ScanRecord]` (`ScanRecord.id`, `.kind`, `.target`, `.hosts`, `.services`, `.findings_count`, `.scanned_at`); `history.kind_for_target(target) -> str | None`; `history.diff_for_target(target, *, since=None) -> DiffResult | None` (`DiffResult.score_before`, `.score_after`, `.new`, `.fixed`, `.unchanged` — each a `list[FindingRecord]`); `history.trend_for_target(target, *, host=None, limit=50) -> list[TrendPoint] | None` (`TrendPoint.scanned_at`, `.score`).
- Produces: `HistoryScreen` (`h` on MainScreen pushes it; `enter` on a row pushes `DetailScreen(target=...)`; `t` pushes `DetailScreen(target=..., trend=True)`; `esc` pops) and `DetailScreen(*, target: str, trend: bool = False)` in `blacklight.tui.views`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_tui.py`:

```python
def test_tui_history_screen_lists_scans(monkeypatch, tmp_path):
    from blacklight import history
    monkeypatch.setattr("blacklight.paths.HOME_DIR", tmp_path)
    history.record_scan("scan", "192.168.1.10", False, {
        "hosts_scanned": 1, "services_found": 1, "findings_count": 0,
        "generated": "2026-08-04T10:00:00+00:00",
    }, [])
    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("h")
            await pilot.pause()
            from textual.widgets import DataTable
            table = app.query_one("#history", DataTable)
            assert table.row_count == 1
            assert table.get_row_at(0)[2] == "192.168.1.10"
            await pilot.press("q")

    asyncio.run(scenario())


def test_tui_history_enter_shows_diff(monkeypatch, tmp_path):
    from blacklight import history
    monkeypatch.setattr("blacklight.paths.HOME_DIR", tmp_path)
    history.record_scan("scan", "192.168.1.10", False, {
        "hosts_scanned": 1, "services_found": 1, "findings_count": 0,
        "generated": "2026-08-04T10:00:00+00:00",
    }, [])
    history.record_scan("scan", "192.168.1.10", False, {
        "hosts_scanned": 1, "services_found": 1, "findings_count": 0,
        "generated": "2026-08-04T11:00:00+00:00",
    }, [])
    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("h")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            from textual.widgets import Label
            title = app.query_one("#detail-title", Label).renderable
            assert "DIFF" in str(title)
            await pilot.press("q")

    asyncio.run(scenario())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tui.py::test_tui_history_screen_lists_scans tests/test_tui.py::test_tui_history_enter_shows_diff -v`
Expected: FAIL — `HistoryScreen` not found.

- [ ] **Step 3: Implement the screens**

Append to `blacklight/tui/views.py`:

```python
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
```

Note: `history.record_scan` signatures in the tests match the ones used by `tests/test_cli.py`; `score_before`/`score_after` are floats in `DiffResult`, and `trend_for_target` returns `None` only when the target was never scanned.

- [ ] **Step 4: Run the new tests**

Run: `python -m pytest tests/test_tui.py -v`
Expected: 7 PASS (3 from Task 2 + 1 run + 1 bridge + 2 history).

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q`
Expected: only the same three prompt_toolkit/`_prompt_html` tests fail or error.

- [ ] **Step 6: Commit**

```bash
git add blacklight/tui/views.py tests/test_tui.py
git commit -m "feat: TUI history list, diff, and trend screens"
```

---

### Task 5: Remove prompt_toolkit

**Files:**
- Modify: `pyproject.toml:13-19` (remove `prompt_toolkit>=3`)
- Modify: `blacklight/console.py` (delete dead `_prompt_html` remnants; confirm no prompt_toolkit references remain)
- Modify: `blacklight/paths.py:8` (delete `CONSOLE_HISTORY`)
- Modify: `tests/test_console.py` (delete the three obsolete tests and the `nullcontext` import if unused)
- Test: `tests/test_console.py`, `tests/test_tui.py`

**Interfaces:**
- Consumes: nothing new
- Produces: a dependency tree without prompt_toolkit; `tests/test_console.py` passes with the TUI replacing REPL coverage

- [ ] **Step 1: Write the failing test (dependency removed)**

Delete the three obsolete tests from `tests/test_console.py`:
- `test_run_interactive_ends_on_exit` (lines ~205-220)
- `test_run_interactive_survives_keyboard_interrupt` (lines ~223-242)
- `test_prompt_html_reflects_active_module` (lines ~245-251)

If `nullcontext` is imported only for those tests, remove that import too.

Then edit `pyproject.toml`:

```toml
dependencies = [
    "typer>=0.12",
    "rich>=13.7",
    "jinja2>=3.1",
    "requests>=2.31",
    "textual>=2.0",
]
```

Edit `blacklight/paths.py` — delete the line:

```python
CONSOLE_HISTORY = HOME_DIR / "console_history"
```

- [ ] **Step 2: Run tests to verify the failures are gone**

Run: `python -m pytest -q`
Expected: the three deleted tests no longer appear; every remaining test PASSES — 241 total (the Task 4 full-suite count of 244 minus the 3 deleted).

Also verify no stray references:

Run: `python -c "import re, pathlib; [print(f) for f in pathlib.Path('blacklight').rglob('*.py') if 'prompt_toolkit' in f.read_text()]"`
Expected: no output.

- [ ] **Step 3: Reinstall dependencies to confirm installability**

Run: `python -m pip install -e .`
Expected: installs cleanly without prompt_toolkit.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml blacklight/console.py blacklight/paths.py tests/test_console.py
git commit -m "chore: remove prompt_toolkit; console interactive mode is now the TUI"
```

---

### Task 6: Failure fallback, acceptance, final suite

**Files:**
- Modify: `blacklight/console.py` — wrap the TUI launch in a try/except fallback
- Test: `tests/test_console.py` (fallback test)

**Interfaces:**
- Consumes: `BlacklightApp.run()`
- Produces: `ConsoleApp._run_interactive` that never propagates TUI startup crashes — it prints a plain hint instead and returns

- [ ] **Step 1: Write the failing test**

Append to `tests/test_console.py`:

```python
def test_run_interactive_falls_back_on_tui_failure(monkeypatch, capsys):
    class BoomApp:
        def __init__(self, *a, **k):
            pass

        def run(self):
            raise RuntimeError("terminal broken")

    monkeypatch.setattr("blacklight.tui.app.BlacklightApp", BoomApp)
    app = ConsoleApp(execute_scan=lambda *a, **k: 0, execute_web=lambda *a, **k: 0)
    app._run_interactive()
    out = capsys.readouterr().out
    assert "interactive mode unavailable" in out
```

(`ConsoleApp` is already imported at the top of `tests/test_console.py` — verify, and add the import if not.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_console.py::test_run_interactive_falls_back_on_tui_failure -v`
Expected: FAIL — the exception propagates.

- [ ] **Step 3: Implement the fallback**

In `blacklight/console.py`, replace `_run_interactive` with a version that imports the app module as a patchable attribute:

```python
    def _run_interactive(self) -> None:
        try:
            from blacklight.tui import app as tui_app

            tui_app.BlacklightApp(
                execute_scan=self.runner.execute_scan,
                execute_web=self.runner.execute_web,
                confirm=self.confirm,
            ).run()
        except Exception:
            theme.make_console(stderr=True).print(
                "[yellow]console: interactive mode unavailable; "
                "pipe commands via stdin instead.[/]"
            )
```

(The function-level `from blacklight.tui import app as tui_app` is safe: `blacklight/tui/app.py` imports `blacklight.console` only for `CommandRunner`, and `console.py` is already fully loaded when `_run_interactive` runs — no circular import. Task 2's Step 5 version can be replaced in place.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_console.py::test_run_interactive_falls_back_on_tui_failure -v`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q`
Expected: 242 PASS (241 from Task 5 + 1 new), 0 FAIL.

- [ ] **Step 6: Manual acceptance**

With the user, in their terminal:
1. `blacklight console` — TUI opens: header, sidebar with `scan`/`web`, options table empty.
2. Enter on `scan` — 7 options appear.
3. Enter on TARGET row — type a target, enter — value shown.
4. `r` — run screen: indeterminate progress, log lines, findings table (or "no findings" note), `esc` back.
5. `h` — history list; enter → diff; `t` → trend; `esc` back.
6. `q` exits, terminal restored cleanly.
7. `echo "modules" | blacklight console` — still prints plain module list (piped path intact).

- [ ] **Step 7: Commit**

```bash
git add blacklight/console.py tests/test_console.py
git commit -m "feat: TUI fallback to plain hint when interactive mode is unavailable"
```

---

## Verification checklist (end of plan)

- [ ] `python -m pytest -q` → 242 passed, 0 failed
- [ ] `python -c "import blacklight.tui"` works; `blacklight console` runs the TUI
- [ ] Piped mode: `echo "modules" | blacklight console` unchanged
- [ ] `python -m pip install -e .` succeeds without prompt_toolkit
- [ ] Design spec constraints honored: engines untouched, CLI commands untouched, `theme.make_console` plain-by-default intact
