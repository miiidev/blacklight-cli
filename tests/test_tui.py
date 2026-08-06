import asyncio

import pytest

from blacklight.tui.app import BlacklightApp


def make_app(execute_scan=None, execute_web=None):
    from blacklight.tui.app import BlacklightApp

    def default_scan(targets, **kwargs):
        return 0

    def default_web(target, **kwargs):
        return 0

    return BlacklightApp(
        execute_scan=execute_scan or default_scan,
        execute_web=execute_web or default_web,
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
            table = app.screen.query_one("#options", DataTable)
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
            table = app.screen.query_one("#options", DataTable)
            table.move_cursor(row=0, column=0)  # TARGET row
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press(*"192.168.1.10", "enter")
            await pilot.pause()
            assert app.runner.state.values["TARGET"] == "192.168.1.10"
            await pilot.press("q")

    asyncio.run(scenario())


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
            table = app.screen.query_one("#options", DataTable)
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