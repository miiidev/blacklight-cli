import asyncio

import pytest

from blacklight.tui.app import BlacklightApp


def make_app(run=None):
    from blacklight.tui.app import BlacklightApp

    def default_run(kind, targets, kwargs):
        return 0

    return BlacklightApp(run=run or default_run)


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


def test_tui_run_invokes_run_with_args():
    calls = []

    def recording_run(kind, targets, kwargs):
        calls.append((kind, targets, kwargs))
        return 0

    app = make_app(run=recording_run)

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
            assert calls[0][0] == "scan"
            assert calls[0][1] == ["192.168.1.10"]
            assert calls[0][2]["timeout"] == 30
            await pilot.press("q")

    asyncio.run(scenario())


def test_tui_run_captures_engine_console(capsys):
    from blacklight import engine

    def noisy_run(kind, targets, kwargs):
        engine.console.print("ENGINE-PROGRESS-LINE")
        engine.console.print("second engine line")
        return 0

    app = make_app(run=noisy_run)

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
            from textual.widgets import Log
            log_lines = app.screen.query_one("#run-log", Log).lines
            assert any("ENGINE-PROGRESS-LINE" in line for line in log_lines)
            captured = capsys.readouterr().out
            assert "ENGINE-PROGRESS-LINE" not in captured
            await pilot.press("q")

    asyncio.run(scenario())


def test_tui_run_progress_bar_tracks_engine():
    from textual.widgets import ProgressBar

    def progress_run(kind, targets, kwargs):
        kwargs["on_progress"]("matching", 0, 4)
        kwargs["on_progress"]("matching", 2, 4)
        kwargs["on_progress"]("matching", 4, 4)
        return 0

    app = make_app(run=progress_run)

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
            bar = app.screen.query_one(ProgressBar)
            assert bar.total == 1
            assert bar.progress == bar.total  # finished at 100%
            await pilot.press("q")

    asyncio.run(scenario())


def test_tui_run_progress_bar_determinate_during_run():
    import time

    from textual.widgets import ProgressBar

    def slow_run(kind, targets, kwargs):
        time.sleep(0.3)
        return 0

    app = make_app(run=slow_run)

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
            bar = app.screen.query_one(ProgressBar)
            assert bar.total == 180  # budget: (timeout 30 * 2) + 120
            await asyncio.sleep(0.4)
            await pilot.pause()
            bar = app.screen.query_one(ProgressBar)
            assert bar.total == 1  # settled at 100% when the run finished
            assert bar.progress == bar.total
            await pilot.press("q")

    asyncio.run(scenario())


def test_confirm_modal_is_centered():
    from blacklight.tui.views import ConfirmModal

    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            await app.push_screen(ConfirmModal("authorize?"))
            await pilot.pause()
            box = app.screen.query_one("#confirm-box")
            assert box.region.x > 0  # not pinned to the left edge
            assert box.region.x + box.region.width < app.screen.size.width
            assert box.region.y > 0  # not pinned to the top edge
            assert box.region.y + box.region.height < app.screen.size.height
            assert box.region.center == (
                app.screen.size.width // 2,
                app.screen.size.height // 2,
            )
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


def test_confirm_bridge_stops_awaiting_when_app_stops():
    import threading

    from blacklight.tui.app import ConfirmBridge

    class FakeApp:
        running = True

        @property
        def is_running(self):
            return self.running

        def call_from_thread(self, fn, *args, **kwargs):
            fn(*args, **kwargs)

        def push_screen(self, screen, callback):
            # modal is shown forever - never answered
            self.modal = screen

    app = FakeApp()
    bridge = ConfirmBridge(app)
    result = []

    def asker():
        result.append(bridge.ask("authorized?"))

    thread = threading.Thread(target=asker, daemon=True)
    thread.start()
    import time
    time.sleep(0.1)
    app.running = False  # user quit mid-prompt
    thread.join(timeout=2)
    assert result == [False]
    assert not thread.is_alive()


def test_confirm_modal_answers_with_y_and_n_keys():
    from blacklight.tui.views import ConfirmModal

    for key, expected in [("y", True), ("n", False)]:
        app = make_app()
        pushed = []

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.push_screen(ConfirmModal("authorize?"), pushed.append)
                await pilot.pause()
                await pilot.press(key)
                await pilot.pause()

        asyncio.run(scenario())
        assert pushed == [expected]


def _scan_result(generated):
    from blacklight.engine import NetworkMeta, ScanResult

    return ScanResult(
        kind="scan", target="192.168.1.10", generated=generated,
        findings=[], web_findings=[],
        meta=NetworkMeta(targets="192.168.1.10", hosts_scanned=1,
                         services_found=1, findings_count=0, generated=generated),
    )


def test_tui_history_screen_lists_scans(monkeypatch, tmp_path):
    from blacklight import history
    monkeypatch.setattr("blacklight.paths.HOME_DIR", tmp_path)
    history.record_scan(_scan_result("2026-08-04T10:00:00+00:00"), False)
    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("h")
            await pilot.pause()
            from textual.widgets import DataTable
            table = app.screen.query_one("#history", DataTable)
            assert table.row_count == 1
            assert table.get_row_at(0)[2] == "192.168.1.10"
            await pilot.press("q")

    asyncio.run(scenario())


def test_tui_uses_tokyo_night_theme():
    from blacklight.tui.app import BlacklightApp
    assert BlacklightApp.theme == "tokyo-night"


def test_tui_history_enter_shows_diff(monkeypatch, tmp_path):
    from blacklight import history
    monkeypatch.setattr("blacklight.paths.HOME_DIR", tmp_path)
    history.record_scan(_scan_result("2026-08-04T10:00:00+00:00"), False)
    history.record_scan(_scan_result("2026-08-04T11:00:00+00:00"), False)
    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("h")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            from textual.widgets import Label
            title = app.screen.query_one("#detail-title", Label).render()
            assert "DIFF" in str(title)
            await pilot.press("q")

    asyncio.run(scenario())