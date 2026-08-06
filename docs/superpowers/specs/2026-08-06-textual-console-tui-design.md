# Textual TUI for `blacklight console` — Design

Date: 2026-08-06
Status: Approved by user (design presented and confirmed), pending spec review

## 1. Context and goal

`blacklight console` currently runs an msfconsole-style line REPL built on
`prompt_toolkit` (`blacklight/console.py`). It prints via rich. The user's
display shows raw ANSI escapes even in ANSI-capable terminals, so rich-based
styling has been reworked to plain-by-default with a `--color` opt-in.

Goal: replace the interactive console's prompt_toolkit REPL with a full-screen
**Textual** TUI — live progress, navigable findings, and keyboard-driven
module/option handling. This is a frontend swap; scan/web engines stay
untouched. TUI is scoped to `blacklight console` only.

## 2. Gate: spike before build

Before any real work, a minimal Textual spike (header + DataTable + progress
bar in one screen) must render correctly in the user's terminal. If the spike
shows a garbled/blank screen, the TUI is abandoned and the current plain
console stays. The spike is a throwaway script, not part of the codebase.

## 3. Scope

In scope:
- `blacklight console` interactive path becomes a Textual TUI.
- Module selection (`scan`/`web`), option editing (`set`/`unset` semantics),
  run with live progress, findings display, history list/diff/trend views.
- Keep the piped (non-tty) console path exactly as-is (`CommandRunner.execute`
  is untouched).
- Remove the `prompt_toolkit` dependency once the REPL is gone.

Out of scope:
- `scan`, `web`, `history`, `version` CLI commands (stay print-and-exit).
- Any change to engines, guardrails, reporter, history storage.
- Replacing rich in non-TUI code.

## 4. Architecture

New package `blacklight/tui/`:

| File | Responsibility |
| --- | --- |
| `app.py` | `BlacklightApp` (Textual `App`): binds keys, composes layout, owns the `CommandRunner`, launches workers |
| `views.py` | Screen/widgets: modules sidebar, options table, findings/log panes, history screens, confirm modal |

`BlacklightApp` holds a `CommandRunner` instance (reused from
`blacklight/console.py`), so module/option state and `execute` semantics are
unchanged and already-tested logic is not duplicated. A `Screen` (or screen
stack) per area:

- **Main screen**: `Header` (title, version, active module), left `ListView`
  with the two modules, main `DataTable` of the active module's options
  (name / current / default / description), `Footer` with keybinding hints.
- **Run screen**: `ProgressBar` + `Log` for scan/web progress and per-host
  output; findings render into a navigable `DataTable` on completion (network
  findings from `execute_scan` meta/findings, web findings from
  `execute_web`).
- **History screen(s)**: reuse `history.list_recent()` /
  `history.diff_for_target()` / `history.trend_for_target()` (data layer
  only; the rich `render_*` functions are not reused), rendered as
  `DataTable`s.

## 5. Data flow

- **Module/option edits** operate directly on `CommandRunner.state` — same
  `ConsoleState`/`Module`/`Option` objects the REPL used.
- **Run**: the TUI reads current module options, then starts a Textual
  `Worker` thread calling `execute_scan` / `execute_web` with the mapped
  arguments. Progress and per-host lines are pushed to the `Log` via
  Textual's worker-to-UI message path (no UI updates from foreign threads).
- **Confirm bridge**: the engines take an injectable `confirm` callback
  (permission prompts). The TUI's confirm callback marshals the question to
  the main thread, shows a `ModalScreen` (yes/no), and returns the answer;
  the worker blocks on the bridge. Same `confirm` plumbing already used by
  the REPL's `_confirm_plain`.
- **History writes**: unchanged — `history.record_scan`/`record_web` are
  called by `execute_scan`/`execute_web` exactly as today.

## 6. Keybindings

| Key | Action |
| --- | --- |
| `q` / `ctrl+q` | Quit |
| `tab` | Cycle focus (sidebar ↔ options ↔ log) |
| `up`/`down` | Navigate lists/tables |
| `enter` | On option: edit value (text input); on module: activate |
| `r` | Run active module |
| `h` | History screen (list; `enter` on a row → diff/trend) |
| `esc` | Back to main screen / dismiss modal |

Exact bindings finalized during implementation; the set above is the
contract.

## 7. Error handling and fallbacks

- `console` invoked with piped stdin → current plain `_run_piped` path,
  unchanged.
- TUI startup failure (non-tty display, crash) → one-line plain error on
  stderr: `console: interactive mode unavailable; pipe commands via stdin`.
- Scan errors inside a worker surface in the run screen (Log + banner),
  never a stack trace over the UI; exit remains the REPL's `0` on success
  and nonzero propagates from `execute_scan`/`execute_web` results.

## 8. Dependencies

- Add `textual>=2.0` to `pyproject.toml` `[project] dependencies`.
- Remove `prompt_toolkit>=3` once `_run_interactive` is deleted and its two
  tests (`tests/test_console.py` lines ~217/236) are replaced with TUI tests.

## 9. Testing

- Textual `App.run_test()` pilot harness for: launch + header assertion,
  module switch, option set, run with mocked `execute_scan`/`execute_web`
  (injected — `ConsoleApp`/TUI receives callables, so monkeypatch is not
  needed), findings table content, history view navigation, quit.
- Existing suites (235 tests) must stay green; `CommandRunner` tests are
  unchanged proof that engine wiring is intact.
- Manual acceptance: spike render check (gate), then a real scan run inside
  the TUI showing live progress and findings.

## 10. Risks

- **ANSI/terminal support (primary)**: Textual needs a working ANSI display
  more than rich does. The spike gate is the control; if it fails, this
  design is void and the current plain console remains.
- Textual API churn between minor versions: pin `textual>=2.0` and keep TUI
  code in one package so it is easy to isolate.
- Worker/UI threading mistakes: mitigated by the confirm bridge and
  worker-message pattern described in section 5.
