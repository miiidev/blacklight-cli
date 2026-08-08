# TUI Splash Landing Screen — Design

Date: 2026-08-08

Status: Approved for planning

## Problem

The interactive console (Textual TUI) boots directly into the module/options
screen with no marker of what the tool is. The user wants a landing page: a
splash screen shown at startup with the blacklight banner, then a keypress
moves into the main screen.

## Decisions (from brainstorming)

- **TUI only.** Piped (non-TTY) console mode and the CLI are untouched.
- **Splash, not dashboard.** Centered banner + caption; no quick-action menu
  and no history summary on it.
- **Keypress dismissal.** Any key (including `q`) dismisses the splash into
  the main screen. `q` must *not* quit the app while the splash is visible.
- **Animation: shimmer + fade in/out.** The banner gradient sweeps colors
  continuously; the screen fades in on mount and fades out on dismissal.

## Approach

A dedicated `SplashScreen(Screen)` mounted above the existing `MainScreen`,
which is pushed first so it is instantly ready underneath.

### Components

**`blacklight/theme.py`**

- `gradient_text(text, phase: float = 0.0)` — new optional `phase` parameter
  that shifts the start column of the purple→cyan interpolation across the
  text width. `phase = 0.0` produces byte-identical output to today's
  implementation, so all existing theme call sites and tests keep passing.
  The shimmer updates `phase` each tick and re-renders.

**`blacklight/tui/views.py` — new `SplashScreen(Screen)`**

- Compose: a centered vertical stack containing
  - a `Static` widget holding the gradient banner text;
  - a caption label: `blacklight-cli v<version> · N modules loaded
    (scan, web)`;
  - a dim prompt: `Press any key to continue`.
- `on_mount`:
  - starts a `set_interval(1/16, self._tick)` shimmer; each tick increments
    the phase and updates the banner `Static` via
    `theme.gradient_text(BANNER, phase)`. The timer lifecycle is owned by the
    screen (Textual removes timers on unmount), so no timer survives into the
    main screen.
  - animates screen opacity from 0 → 1 over ~0.4 s (Textual `animate` on the
    screen/widget), one-shot.
- Dismissal: `BINDINGS = [("q", "dismiss", "")]` plus an `on_key` handler so
  any key dismisses. Dismissal sequence:
  1. stop the shimmer timer;
  2. set a `_dismissing` flag so further key events are ignored (prevents
     double-pops during the fade);
  3. animate opacity 1 → 0 over ~0.3 s with `on_complete` that calls
     `app.pop_screen()`, revealing the already-mounted `MainScreen`.
- On-screen `q` binding shadows the app-level `q` → quit binding, so pressing
  `q` during the splash only dismisses.

**`blacklight/tui/app.py`**

- `BlacklightApp.on_mount` pushes `MainScreen()` first, then
  `SplashScreen()` on top of the stack.

**Untouched:** `CommandRunner`/`ConsoleState`, `ConsoleApp` piped/header
paths, `cli.py`, the engine.

## Error-handling / edge cases

- Repeated keypresses during the fade-out are ignored via `_dismissing`.
- The shimmer timer stops before the fade so the fade-out shows a static
  banner (no jarring color sweep mid-fade).
- `gradient_text` keeps its existing defensive handling of empty input and
  single-column lines with `phase`.
- If the TUI falls back to piped mode (console interactive unavailable), no
  splash exists — no change to that path.

## Testing

**`tests/test_theme.py`**

- `gradient_text(text, phase=0)` output is unchanged from today.
- Two different `phase` values produce different styles/colors; a full cycle
  (phase that wraps column interpolation) returns the original style at the
  equivalent frame.

**`tests/test_tui.py`**

- New `test_splash_shown_on_launch`: launching the app shows the splash as
  the active screen; banner and caption containing the version are visible.
- New `test_splash_any_key_dismisses_to_main_screen`: splash dismisses on a
  key press and the main screen takes over (options table present).
- New `test_splash_q_dismisses_not_quits`: pressing `q` on the splash lands
  on the main screen; the app is still running.
- Existing 9 TUI driver tests: each starts with a leading keypress to clear
  the splash before interacting with the main screen (their assertions are
  unchanged). `test_tui_launches_and_quits` presses `q` twice: once to
  dismiss the splash, once to quit.

## Out of scope

- Optional skip flag (`--no-splash` / setting): explicitly deferred; can be a
  follow-up if the splash annoys.
- Landing-page dashboard (recent history summary, quick actions).
- Any change to piped console or CLI behavior.
- Third-party transition libraries (e.g. textual-effects).