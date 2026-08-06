import io

from blacklight.console import CommandRunner, ConsoleApp


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


def test_web_run_warns_when_multiple_targets():
    captured = {}

    def fake_web(url, **kwargs):
        captured["url"] = url
        return 0

    runner, out = run_commands(
        ["use web", "set TARGET http://127.0.0.1,http://alias.example", "run"],
        make_runner(execute_web=fake_web),
    )
    assert captured["url"] == "http://127.0.0.1"
    assert "web accepts a single TARGET" in out


def test_run_rejects_non_positive_timeout():
    called = []

    def fake_scan(targets, **kwargs):
        called.append(targets)
        return 0

    _, out = run_commands(
        ["use scan", "set TIMEOUT 0", "run"],
        make_runner(execute_scan=fake_scan),
    )
    assert "TIMEOUT must be a positive integer" in out
    assert called == []





from typer.testing import CliRunner

from blacklight.cli import app

runner = CliRunner()


def test_console_command_piped_session(monkeypatch):
    seen = []

    def fake_scan(targets, **kwargs):
        seen.append((targets, kwargs))
        return 0

    monkeypatch.setattr("blacklight.cli.execute_scan", fake_scan)
    result = runner.invoke(
        app, ["console"],
        input="use scan\nset TARGET 192.168.1.10\nrun\nexit\n",
    )
    assert result.exit_code == 0
    assert "modules loaded (scan, web)" in result.output
    assert "Type 'help'" in result.output
    assert "Using module scan" in result.output
    assert len(seen) == 1
    targets, kwargs = seen[0]
    assert targets == ["192.168.1.10"]
    assert kwargs["permission_granted"] is False


def test_bare_invocation_shows_help(monkeypatch):
    monkeypatch.setattr("blacklight.cli.execute_scan", lambda *a, **k: 0)
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "██████╗" in result.output
    assert "scan" in result.output
    assert "console" in result.output
    assert "modules loaded" not in result.output


def test_console_history_lists_scans(monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    from blacklight import history

    history.record_scan("scan", "192.168.1.10", False, {
        "hosts_scanned": 1, "services_found": 1, "findings_count": 0,
        "generated": "2026-08-04T10:00:00+00:00",
    }, [])
    _, out = run_commands(["history"])
    assert "192.168.1.10" in out


def test_console_history_empty_warns():
    _, out = run_commands(["history"])
    assert "No scan history yet" in out


def test_console_history_with_target_diffs():
    from blacklight import history
    from blacklight.cve_matcher import Finding

    finding = Finding(
        host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
        cpe="cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*:*",
        cve_id="CVE-2024-0001", description="t", cvss_score=8.1,
        severity="high", fixed_version="9.7")
    meta = {"hosts_scanned": 1, "services_found": 1, "findings_count": 1,
            "generated": "2026-08-04T10:00:00+00:00"}
    history.record_scan("scan", "192.168.1.10", False, meta, [finding])
    history.record_scan("scan", "192.168.1.10", False,
                        dict(meta, generated="2026-08-04T11:00:00+00:00"), [])
    _, out = run_commands(["history 192.168.1.10"])
    assert "Risk score:" in out
    assert "improved" in out


def test_console_history_unknown_target_warns():
    _, out = run_commands(["history 10.0.0.99"])
    assert "No scans of 10.0.0.99 yet." in out


def test_console_history_usage_error():
    _, out = run_commands(["history a b"])
    assert "Usage: history [<target>]" in out


def test_console_trend_renders():
    from blacklight import history

    meta = {"hosts_scanned": 1, "services_found": 1, "findings_count": 0,
            "generated": "2026-08-04T10:00:00+00:00"}
    history.record_scan("scan", "192.168.1.10", False, meta, [])
    history.record_scan("scan", "192.168.1.10", False,
                        dict(meta, generated="2026-08-04T11:00:00+00:00"), [])
    _, out = run_commands(["trend 192.168.1.10"])
    assert "Risk trend for 192.168.1.10" in out
    assert "0.0" in out


def test_console_trend_unknown_target_warns():
    _, out = run_commands(["trend 10.0.0.99"])
    assert "No scans of 10.0.0.99 yet." in out


def test_console_trend_usage_error():
    _, out = run_commands(["trend"])
    assert "Usage: trend <target>" in out


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