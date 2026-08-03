import io

from blacklight.console import CommandRunner


def make_runner(**overrides):
    kwargs = {
        "execute_scan": lambda *a, **k: 0,
        "execute_web": lambda *a, **k: 0,
        "confirm": lambda m: True,
    }
    kwargs.update(overrides)
    return CommandRunner(**kwargs)


def run_commands(lines, runner=None):
    runner = runner or make_runner()
    out = io.StringIO()
    for line in lines:
        runner.execute(line, out)
    return runner, out.getvalue()


def test_help_lists_all_commands():
    _, out = run_commands(["help"])
    for word in ("help", "modules", "use", "show options", "set", "unset",
                 "run", "back", "exit"):
        assert word in out


def test_modules_lists_scan_and_web():
    _, out = run_commands(["modules"])
    assert "scan" in out
    assert "web" in out


def test_use_selects_module():
    runner, out = run_commands(["use scan"])
    assert runner.state.active == "scan"
    assert "Using module scan" in out


def test_use_unknown_module_errors_and_keeps_state():
    runner, out = run_commands(["use nope"])
    assert runner.state.active is None
    assert "Unknown module" in out


def test_set_stores_value():
    runner, _ = run_commands(["use scan", "set TARGET 192.168.1.10"])
    assert runner.state.values["TARGET"] == "192.168.1.10"


def test_set_unknown_option_errors():
    _, out = run_commands(["use scan", "set NOPE x"])
    assert "Unknown option: NOPE" in out


def test_set_permission_rejects_non_boolean():
    _, out = run_commands(["use scan", "set PERMISSION maybe"])
    assert "PERMISSION expects true or false" in out


def test_set_before_use_hints():
    _, out = run_commands(["set TARGET 192.168.1.10"])
    assert "No module selected" in out


def test_unset_restores_default():
    runner, _ = run_commands(["use scan", "set TARGET 192.168.1.10", "unset TARGET"])
    assert "TARGET" not in runner.state.values


def test_show_options_lists_active_module_options():
    _, out = run_commands(["use web", "show options"])
    assert "TARGET" in out
    assert "PERMISSION" in out
    assert "http(s)" in out


def test_run_requires_module():
    _, out = run_commands(["run"])
    assert "No module selected" in out


def test_run_requires_target():
    _, out = run_commands(["use scan", "run"])
    assert "TARGET not set" in out


def test_run_invokes_execute_scan_with_converted_options():
    captured = {}

    def fake_scan(targets, **kwargs):
        captured["targets"] = targets
        captured.update(kwargs)
        return 0

    runner, out = run_commands(
        ["use scan", "set TARGET 192.168.1.10,192.168.1.20",
         "set PERMISSION true", "run"],
        make_runner(execute_scan=fake_scan),
    )
    assert captured["targets"] == ["192.168.1.10", "192.168.1.20"]
    assert captured["permission_granted"] is True
    assert captured["ports"] == "1-1024"
    assert captured["timeout"] == 30
    assert captured["no_cache"] is False
    assert captured["fmt"] == "html"
    assert captured["output"] is None
    assert "Done" in out


def test_run_invokes_execute_web_with_first_target():
    captured = {}

    def fake_web(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return 0

    runner, _ = run_commands(
        ["use web", "set TARGET http://127.0.0.1", "run"],
        make_runner(execute_web=fake_web),
    )
    assert captured["url"] == "http://127.0.0.1"
    assert captured["permission_granted"] is False


def test_run_forwards_injected_confirm():
    confirm_cb = lambda m: False  # noqa: E731
    captured = {}

    def fake_scan(targets, **kwargs):
        captured.update(kwargs)
        return 0

    run_commands(
        ["use scan", "set TARGET 8.8.8.8", "set PERMISSION true", "run"],
        make_runner(execute_scan=fake_scan, confirm=confirm_cb),
    )
    assert captured["confirm"] is confirm_cb


def test_run_rejects_non_integer_timeout():
    _, out = run_commands(["use scan", "set TIMEOUT abc", "run"])
    assert "TIMEOUT must be an integer" in out


def test_back_clears_active_module():
    runner, out = run_commands(["use scan", "back"])
    assert runner.state.active is None
    runner, out = run_commands(["back"])
    assert "No module selected" in out


def test_exit_and_quit_return_true():
    runner = make_runner()
    assert runner.execute("exit", io.StringIO()) is True
    assert runner.execute("quit", io.StringIO()) is True


def test_unknown_command_hints():
    _, out = run_commands(["frobnicate"])
    assert "Unknown command: frobnicate" in out


def test_empty_and_blank_lines_are_noops():
    runner = make_runner()
    assert runner.execute("", io.StringIO()) is False
    assert runner.execute("   ", io.StringIO()) is False