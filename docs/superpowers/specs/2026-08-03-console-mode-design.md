# Interactive Console Mode — Design

Date: 2026-08-03
Status: Approved (pending spec review)

## Goal

Add an msfconsole-style interactive session to blacklight-cli: launch once,
`use` a module, `set` options, `run`, stay in the REPL. Reuses the existing
scan/web engines and guardrails unchanged.

Source: `docs/blacklight-cli-handoff.md` §3 (design agreed with user on
2026-08-03, with the user additions: an explicit `blacklight console`
subcommand alongside bare-invocation entry, and `unset` + a `permission`
option).

## User decisions (from brainstorming)

1. Shared orchestration: extract the pipeline the `scan()`/`web()` commands
   embed into shared functions with an injectable `confirm` callback; both the
   CLI commands and the console call them (no duplicated logic, no drift).
2. Entry points: bare `blacklight` (no subcommand) drops into the console;
   `blacklight console` does the same explicitly. `--help` unchanged.
3. Command set: `help`, `modules`, `use`, `show options`, `set`, `unset`,
   `run`, `back`, `exit`/`quit`.
4. `permission` option per module (default off): true mirrors
   `--i-have-permission` and skips the interactive authorization confirm.
5. Library: `prompt_toolkit` (new required dependency) for tab-completion,
   arrow-key history, styled prompt.
6. Version bump to `0.2.0` with this feature.

## Architecture

### Files

| File | Change | Responsibility |
|---|---|---|
| `blacklight/console.py` | **new** | REPL: `CommandRunner` (pure, testable), module model, `ConsoleApp` loop |
| `blacklight/cli.py` | modified | Extract `execute_scan`/`execute_web`; thin `scan`/`web` commands; `console` command; bare-invocation → console |
| `pyproject.toml` | modified | Add `prompt_toolkit>=3`; version `0.2.0` |
| `tests/test_console.py` | **new** | Command dispatch + REPL loop tests |
| `tests/test_cli.py` | modified | Tests for `execute_scan`/`execute_web` (confirm injection, permission=false/true, blocked) |
| everything else | untouched | scanner, cve_matcher, enrichment, scoring, cpe_map, guardrails, reporter, theme, web engine |

### Shared orchestration (in `blacklight/cli.py`)

```python
def execute_scan(targets, *, ports, timeout, no_cache, output, fmt,
                 permission_granted, confirm) -> int:
    """Verify targets under guardrails, run the scan pipeline, log,
    render, and export. Returns the process exit code (0 or 1)."""

def execute_web(url, *, timeout, no_cache, output, fmt,
                permission_granted, confirm) -> int:
    """Same shape for web targets."""
```

Behavior (identical to today's CLI commands):
1. `paths.ensure_dirs()`.
2. Guardrail verify (`guardrails.verify_targets` / `verify_web_target`).
3. Print blocked reasons; compile scannable list = allowed + needs-confirmation.
4. For each needs-confirmation (public, permission-claimed) target, call
   `confirm(message)`; abort on `False`. Targets blocked by the guardrails are
   reported without prompting (when `permission_granted=False`).
5. Run (`run_scan` / `run_web_scan`); `_log_scan` / `_log_web_scan`.
6. `render_terminal(...)`.
7. Export if `output` set; print the report path.

`scan`/`web` commands become thin wrappers calling these with
`confirm=typer.confirm` and `permission_granted=i_have_permission`. The
console calls them with its own `confirm` (a `prompt_toolkit` prompt) and
`permission_granted=state["PERMISSION"]`.

The `permission_granted` parameter carries today's `--i-have-permission`
semantics exactly:
- `permission_granted=False` → public targets are blocked outright, no prompt
  (matches today's CLI without the flag).
- `permission_granted=True` → public targets move to needs-confirmation and the
  injected `confirm(message)` callback decides. The CLI passes `typer.confirm`;
  the console passes its own prompt.

### Console model

```python
@dataclass
class Module:
    name: str            # "scan" | "web"
    description: str
    options: dict[str, Option]   # key -> Option(default, help)

@dataclass
class ConsoleState:
    modules: dict[str, Module]
    active: str | None           # selected module name
    values: dict[str, str]       # set option values (str, incl. bools "true"/"false")
```

Options are mirrors of the CLI flags:

| Module | Option | Default | CLI flag |
|---|---|---|---|
| scan | TARGET | "" | positional |
| scan | PORTS | "1-1024" | `--ports` |
| scan | OUTPUT | "" | `--output` |
| scan | FORMAT | "html" | `--format` |
| scan | NO_CACHE | "false" | `--no-cache` |
| scan | TIMEOUT | "30" | `--timeout` |
| scan | PERMISSION | "false" | `--i-have-permission` |
| web | TARGET | "" | positional |
| web | TIMEOUT | "30" | `--timeout` |
| web | NO_CACHE | "false" | `--no-cache` |
| web | OUTPUT | "" | `--output` |
| web | FORMAT | "html" | `--format` |
| web | PERMISSION | "false" | `--i-have-permission` |

### Command dispatch (`CommandRunner`)

`CommandRunner.execute(line: str, out: TextIO) -> bool`
- Parses and dispatches one input line, writing any output to `out`.
- Returns `True` when the loop should exit (`exit`/`quit`), else `False`.
- prompt_toolkit-free by design: the scan/web pipeline and the confirm
  callback are injected as callables, so the runner is fully unit-testable.

Commands:
- `help` — usage text.
- `modules` — table of modules (name/description, reusing `reporter`-style
  rich table via a thin console, or plain text into `out`).
- `use <name>` — select module; set `active`; error on unknown module.
- `show options` — table of active module's options with current values.
- `set <OPTION> <value>` — store; validate the option name; `PERMISSION`
  accepts `true`/`false`; error otherwise.
- `unset <OPTION>` — restore option to its default.
- `run` — require active module AND a non-empty TARGET; build arg dict,
  call the injected `execute_scan`/`execute_web`; print result.
- `back` — clear active module (back to top-level prompt).
- `exit` / `quit` — signal loop termination.
- Unknown command — error hint.

Option → arg conversion in `run`: PORTS/OUTPUT/TIMEOUT/NO_CACHE/FORMAT map
to the `execute_scan` kwargs; TARGET becomes the target(s); PERMISSION →
`permission_granted`. Target list: split on commas/whitespace.

### REPL loop (`ConsoleApp`)

- `ConsoleApp(confirm: Callable[[str], bool] | None = None)`.
- Non-interactive (stdin not a tty or `--` piped): simple `input()` loop,
  so `echo "run\nexit" | blacklight console` works; each command printed to
  stdout.
- Interactive: `prompt_toolkit.PromptSession` with:
  - theme-styled prompt: `blacklight > ` (top level, cyan) and
    `blacklight (scan) > ` (module active, purple).
  - tab completion for command names, module names, and option keys.
  - history persisted at `~/.blacklight/console_history`.
- On first start: print `theme.print_banner(console)` then header
  `blacklight-cli v0.2.0 — 2 modules loaded (scan, web)` + "Type 'help'…".
- `patch_stdout` wraps the rich terminal output during `run` so the prompt
  line redraws cleanly.
- Errors during a command print a `[red]` line and return to the prompt
  (no crash, exit code 0); `exit` ends with exit code 0.
- EOF (Ctrl-D) ends the loop.

### Entry points (cli.py)

- `@app.command() def console(...)` — calls `ConsoleApp().run()`.
- Bare invocation: currently typer errors (exit 2, "Missing command"). Add a
  callback with `invoke_without_command=True`; when `typer.Context` ran with
  no subcommand (`ctx.invoked_subcommand is None`), run the console. This
  preserves `--help` behavior (help rendering short-circuits before the
  callback's console path).
- `scan`/`web` commands unchanged in signature and flags.

### Error handling

| Case | Behavior |
|---|---|
| `use <unknown>` | `[red]Unknown module[/]` + list; no state change |
| `run` without `active` | `[red]No module selected. Use 'use <module>' first.[/]` |
| `run` with TARGET="" | `[red]TARGET not set.[/]` |
| `set PERMISSION foo` | `[red]PERMISSION expects true or false.[/]` |
| stdin not a tty | readline-less input loop (no completion/history); tests use this path |
| scan/web runtime error (same exceptions as today) | `execute_*` returns 1 and prints `Scan failed/` as today; console stays up |
| Ctrl-D at prompt | clean exit, code 0 |

### Testing

- `CommandRunner`: `use scan`, `use nope`, `set TARGET x`/`set NOPE x`/
  `set PERMISSION foo`, unset, run-before-use, modules/help/exit — table of
  `(input line, expected output substring)` driven without prompt_toolkit.
- `execute_scan`/`execute_web` (in `tests/test_cli.py`): with monkeypatched
  `scanner.scan_hosts` + fake `NvdClient` + `enrichment` (patterns from
  existing tests): blocked public target without permission (no scan call,
  code 1); public + `permission_granted=True` + `confirm->False` aborts;
  `confirm->True` proceeds; private targets never prompt; export path writes
  file when OUTPUT set.
- REPL smoke (non-tty): feed `modules\nuse scan\nset TARGET 192.168.1.10\nrun\nback\nexit\n` with monkeypatched `run` path so it does no network — assets prompt text and final exit code 0.
- Full existing suite (149 tests) stays green.
- Manual smoke: `blacklight`, `blacklight console`, `echo "exit" | blacklight console`, tab-completion in a real terminal.

## Dependencies & packaging

- `pyproject.toml`: add `"prompt_toolkit>=3"` to `dependencies`.
- Lazy import: `cli.py` imports `console` module only inside the `console`
  command / bare-invocation path, so `scan`/`web`/`version` never load
  prompt_toolkit.
- Version: `0.2.0` in `pyproject.toml` and the `__version__` constant.
- Reinstall editable after dependency add (dev machine).

## Out of scope

- SQLite history store, diffing, accept/suppress (next sub-project).
- TLS/cert module, SARIF/fail-on, notifications, profiles, target-file (later
  sub-projects).
- Adding new scan options beyond the existing flag set.
- Changing `scan`/`web` CLI flag names or semantics.