# TUI Splash Landing Screen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show an animated splash landing screen (gradient shimmer + fade in/out) when the interactive Textual console launches; any key dismisses it into the main screen.

**Architecture:** A dedicated `SplashScreen(Screen)` in `blacklight/tui/views.py` is pushed on top of the already-mounted `MainScreen` in `BlacklightApp.on_mount`. The shimmer re-renders `theme.gradient_text(BANNER, phase)` on a `set_interval` timer; dismissal stops the timer and fades the screen out before popping. `theme.gradient_text` gains an optional `phase` parameter (default `0.0` is byte-identical to today).

**Tech Stack:** Python 3.11+, Textual 8.2.8 (already installed), rich `Text` renderables, pytest.

## Global Constraints

- Textual API floor: `widget.animate("opacity", value, duration=..., on_complete=...)`, `set_interval(interval, callback)`, `Screen` opacity CSS/`styles.opacity` — all verified present in installed Textual 8.2.8.
- `theme.gradient_text(text, phase=0.0)` with `phase=0.0` MUST produce byte-identical output to the current implementation (existing callers and tests must not change).
- Any key dismisses the splash — including `q` (the screen-level `q` binding shadows the app-level quit binding). `q` on the splash must NOT quit the app.
- Repeated keypresses during the fade-out must be ignored (`_dismissing` flag) — no double-pop.
- The shimmer timer must be stopped before the fade-out, and Textual removes screen timers on unmount (no timer leaks into MainScreen).
- Piped (non-TTY) console mode, `CommandRunner`, `ConsoleApp`, `cli.py`, and the engine are untouched.
- Test runner: `python -m pytest` from the repo root (`testpaths = ["tests"]`).
- Commit messages follow repo style: `feat:`, `test:`, `docs:` prefixes.

---

### Task 1: `gradient_text` phase parameter

**Files:**
- Modify: `blacklight/theme.py` (the `gradient_text` function, lines 45-61)
- Test: `tests/test_theme.py`

**Interfaces:**
- Consumes: existing `theme.PURPLE`, `theme.CYAN`, `theme._lerp_hex` (internal).
- Produces: `gradient_text(text: str, phase: float = 0.0) -> rich.text.Text` — `phase` shifts the gradient start column; values wrap modulo the banner width; `phase=0.0` is identical to the pre-change output.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_theme.py`:

```python
def test_gradient_text_phase_zero_is_unchanged():
    before = theme.gradient_text(theme.BANNER)
    after = theme.gradient_text(theme.BANNER, phase=0.0)
    assert after.plain == before.plain
    assert after.spans == before.spans


def test_gradient_text_phase_shifts_colors():
    base = theme.gradient_text(theme.BANNER)
    shifted = theme.gradient_text(theme.BANNER, phase=0.5)
    first_color = next(
        s.style.color for s in base.spans if s.style and s.style.color
    )
    shifted_color = next(
        s.style.color for s in shifted.spans if s.style and s.style.color
    )
    assert shifted_color != first_color


def test_gradient_text_full_phase_cycle_returns_to_start():
    start = theme.gradient_text(theme.BANNER, phase=0.0)
    wrapped = theme.gradient_text(theme.BANNER, phase=1.0)
    assert wrapped.plain == start.plain
    assert wrapped.spans == start.spans
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_theme.py::test_gradient_text_phase_zero_is_unchanged tests/test_theme.py::test_gradient_text_phase_shifts_colors tests/test_theme.py::test_gradient_text_full_phase_cycle_returns_to_start -v`
Expected: FAIL — `TypeError: gradient_text() got an unexpected keyword argument 'phase'`

- [ ] **Step 3: Implement the `phase` parameter**

In `blacklight/theme.py`, replace the `gradient_text` function body (keep the docstring, update it):

```python
def gradient_text(text: str, phase: float = 0.0) -> Text:
    """Render text with a purple-to-cyan gradient across its width.

    ``phase`` in [0, 1) shifts the start column of the gradient; values wrap
    modulo the text width, so phase=0.0 is the default and phase=1.0 is
    identical to phase=0.0.
    """
    lines = text.splitlines()
    if not lines:
        return Text()
    max_width = max(len(line) for line in lines)
    out = Text()
    width = max(max_width - 1, 1)
    for i, line in enumerate(lines):
        for col, ch in enumerate(line):
            if ch == " ":
                out.append(" ")
            else:
                t = ((col + phase * max_width) % max_width) / width
                out.append(ch, style=_lerp_hex(PURPLE, CYAN, t))
        if i < len(lines) - 1:
            out.append("\n")
    return out
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_theme.py -v`
Expected: all pass (including the pre-existing gradient/banner tests, proving `phase=0.0` is backward compatible).

- [ ] **Step 5: Commit**

```bash
git add blacklight/theme.py tests/test_theme.py
git commit -m "feat: gradient_text phase parameter for banner shimmer"
```

---

### Task 2: `SplashScreen` + app wiring + tests

**Files:**
- Modify: `blacklight/tui/views.py` (add imports + `SplashScreen` class)
- Modify: `blacklight/tui/app.py` (imports + `on_mount`)
- Test: `tests/test_tui.py` (3 new tests + helper + updates to 9 existing tests)

**Interfaces:**
- Consumes: `theme.gradient_text(text, phase)` from Task 1; `theme.BANNER`; `__version__` from `blacklight`; `app.runner.state.modules` (a `dict[str, Module]` set by `BlacklightApp.on_mount` before any screen is pushed).
- Produces: `SplashScreen(Screen)` with `BINDINGS = [("q", "dismiss", "Dismiss")]`, an `on_key` handler, and a `_dismiss()` method that stops the shimmer, sets `_dismissing`, fades opacity to 0 and `pop_screen()`s on completion.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_tui.py` (after the existing `make_app` helper and tests):

```python
async def dismiss_splash(pilot):
    await pilot.press("space")
    await pilot.pause()
    await asyncio.sleep(0.4)  # fade-out duration; pop_screen runs on_complete
    await pilot.pause()


def test_splash_shown_on_launch():
    from blacklight import __version__
    from blacklight.tui.views import SplashScreen

    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, SplashScreen)
            banner = app.screen.query_one("#splash-banner")
            assert "██████╗" in str(banner.render())
            caption = app.screen.query_one("#splash-caption")
            assert __version__ in str(caption.render())
            await dismiss_splash(pilot)
            await pilot.press("q")

    asyncio.run(scenario())


def test_splash_any_key_dismisses_to_main_screen():
    from blacklight.tui.views import MainScreen

    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            await dismiss_splash(pilot)
            from textual.widgets import DataTable
            assert isinstance(app.screen, MainScreen)
            assert app.screen.query_one("#options", DataTable)
            await pilot.press("q")

    asyncio.run(scenario())


def test_splash_q_dismisses_not_quits():
    from blacklight.tui.views import MainScreen, SplashScreen

    app = make_app()

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, SplashScreen)
            await pilot.press("q")
            await pilot.pause()
            await asyncio.sleep(0.4)
            await pilot.pause()
            assert app.is_running
            assert isinstance(app.screen, MainScreen)
            await pilot.press("q")

    asyncio.run(scenario())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tui.py::test_splash_shown_on_launch tests/test_tui.py::test_splash_any_key_dismisses_to_main_screen tests/test_tui.py::test_splash_q_dismisses_not_quits -v`
Expected: FAIL — `ImportError: cannot import name 'SplashScreen'`

- [ ] **Step 3: Implement `SplashScreen` in `blacklight/tui/views.py`**

Update the imports at the top of `blacklight/tui/views.py`:

```python
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
```

Add the `SplashScreen` class at the top of the file (above `MainScreen`, after `capture_engine_output`):

```python
class SplashScreen(Screen):
    """Startup landing screen: animated gradient banner; any key dismisses."""

    CSS = """
    SplashScreen {
        align: center middle;
    }
    #splash-box {
        width: auto;
        height: auto;
        align: center middle;
    }
    #splash-caption {
        margin-top: 1;
        color: $text-muted;
        text-align: center;
    }
    #splash-prompt {
        margin-top: 2;
        color: $text-dim;
        text-align: center;
    }
    """

    BINDINGS = [("q", "dismiss", "Dismiss")]

    SHIMMER_INTERVAL = 1 / 16
    PHASE_STEP = 1 / 64
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
        self._timer = self.set_interval(self.SHIMMER_INTERVAL, self._tick)
        self.styles.opacity = 0.0
        self.animate("opacity", 1.0, duration=self.FADE_MS / 1000)

    def _tick(self) -> None:
        self._phase = (self._phase + self.PHASE_STEP) % 1.0
        banner = self.query_one("#splash-banner", Static)
        banner.update(theme.gradient_text(theme.BANNER, phase=self._phase))

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
        self.animate(
            "opacity",
            0.0,
            duration=self.DISMISS_MS / 1000,
            on_complete=lambda: self.app.pop_screen(),
        )
```

- [ ] **Step 4: Wire the splash into `blacklight/tui/app.py`**

Update the import on line 10:

```python
from blacklight.tui.views import ConfirmModal, MainScreen, SplashScreen
```

Replace `on_mount` (lines 55-60):

```python
    def on_mount(self) -> None:
        self.runner = CommandRunner(
            run=self._run,
            confirm=self._confirm or self._bridge.ask,
        )
        self.push_screen(MainScreen())
        self.push_screen(SplashScreen())
```

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `python -m pytest tests/test_tui.py::test_splash_shown_on_launch tests/test_tui.py::test_splash_any_key_dismisses_to_main_screen tests/test_tui.py::test_splash_q_dismisses_not_quits -v`
Expected: all PASS.

- [ ] **Step 6: Update the 9 existing TUI driver tests**

The splash now intercepts the first keypress of every launch. In each of the 9
tests below, insert `await dismiss_splash(pilot)` immediately after the
`await pilot.pause()` that follows `async with app.run_test() as pilot:`.
The existing assertions and subsequent keypresses stay unchanged.

| Test | Key-sequence change |
|---|---|
| `test_tui_launches_and_quits` | `q` → `space` (dismiss) then `q` (quit from main screen) |
| `test_tui_lists_modules_and_activates_scan` | first `enter` → `space` then `enter` |
| `test_tui_edits_option_value` | first `enter` → `space` then `enter` |
| `test_tui_run_invokes_run_with_args` | first `enter` → `space` then `enter` |
| `test_tui_run_captures_engine_console` | first `enter` → `space` then `enter` |
| `test_tui_run_progress_bar_tracks_engine` | first `enter` → `space` then `enter` |
| `test_tui_run_progress_bar_determinate_during_run` | first `enter` → `space` then `enter` |
| `test_tui_history_screen_lists_scans` | first `h` → `space` then `h` |
| `test_tui_history_enter_shows_diff` | first `h` → `space` then `h` |

Example of the pattern used (`test_tui_lists_modules_and_activates_scan`, after
its existing first `await pilot.pause()`):

```python
            await pilot.pause()
            await dismiss_splash(pilot)
            await pilot.press("enter")  # select first module (scan)
```

- [ ] **Step 7: Run the full test suite**

Run: `python -m pytest -v`
Expected: all tests pass (theme, console, TUI, engine, etc.).

- [ ] **Step 8: Commit**

```bash
git add blacklight/tui/views.py blacklight/tui/app.py tests/test_tui.py
git commit -m "feat: TUI splash landing screen with shimmer and fade"
```
