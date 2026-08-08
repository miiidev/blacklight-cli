from rich.console import Console

from blacklight import theme


def test_banner_lines_are_clean_and_narrow():
    for line in theme.BANNER.splitlines():
        assert len(line) <= 80
        assert line == line.rstrip()


def test_banner_has_wordmark():
    assert len(theme.BANNER.splitlines()) >= 6
    assert "██████╗" in theme.BANNER


def test_gradient_text_empty_returns_empty_text():
    text = theme.gradient_text("")
    assert text.plain == ""


def test_gradient_text_preserves_content_and_colors():
    text = theme.gradient_text(theme.BANNER)
    assert text.plain == theme.BANNER
    styled = [span for span in text.spans if span.style]
    assert styled


def test_print_banner_skips_narrow_console():
    console = Console(record=True, width=60)
    theme.print_banner(console)
    assert console.export_text() == ""


def test_print_banner_prints_on_wide_console():
    console = Console(record=True, width=160)
    theme.print_banner(console)
    assert "██████╗" in console.export_text()


def test_risk_gauge_band_colors():
    assert "green" in theme.risk_gauge(0.0)
    assert "green" in theme.risk_gauge(29.9)
    assert "yellow" in theme.risk_gauge(30.0)
    assert "yellow" in theme.risk_gauge(59.9)
    assert "dark_orange" in theme.risk_gauge(60.0)
    assert "dark_orange" in theme.risk_gauge(79.9)
    assert "red" in theme.risk_gauge(80.0)
    assert "red" in theme.risk_gauge(100.0)


def test_risk_gauge_fill_counts():
    assert theme.risk_gauge(0.0) == "[green]░░░░░░░░░░[/] 0.0"
    assert theme.risk_gauge(25.0).startswith("[green]███")
    assert theme.risk_gauge(72.4).startswith("[dark_orange]███████")
    assert theme.risk_gauge(100.0) == "[red]██████████[/] 100.0"


def test_risk_gauge_clamps():
    assert theme.risk_gauge(-5) == "[green]░░░░░░░░░░[/] 0.0"
    assert theme.risk_gauge(150) == "[red]██████████[/] 100.0"
    assert theme.risk_gauge(72.4).endswith("72.4")


def test_enable_windows_vt_is_safe():
    theme.enable_windows_vt()


def test_make_console_plain_by_default():
    from collections import ChainMap

    console = theme.make_console()
    assert console.color_system is None
    assert isinstance(console._environ, ChainMap)
    assert console._environ.get("TERM") == "dumb"


def test_make_console_color_opts_into_ansi(monkeypatch):
    from collections import ChainMap

    monkeypatch.delenv("NO_COLOR", raising=False)
    console = theme.make_console(color=True)
    assert not isinstance(console._environ, ChainMap)
    assert console._environ.get("TERM") != "dumb"


def test_no_color_wins_over_color_option(monkeypatch):
    from collections import ChainMap

    monkeypatch.setenv("NO_COLOR", "1")
    console = theme.make_console(color=True)
    assert isinstance(console._environ, ChainMap)
    assert console._environ.get("TERM") == "dumb"


def test_make_console_environ_reads_live_columns(monkeypatch):
    console = theme.make_console()
    monkeypatch.setenv("COLUMNS", "180")
    expected = 180 - (1 if console.legacy_windows else 0)
    assert console.width == expected


def test_palette_uses_tokyo_night_colors():
    assert theme.PURPLE == "#BB9AF7"
    assert theme.CYAN == "#7AA2F7"
    assert theme.ACCENT == "#BB9AF7"
    assert theme.DIM == "#6b7280"


def test_gradient_text_phase_zero_is_unchanged():
    before = theme.gradient_text(theme.BANNER)
    after = theme.gradient_text(theme.BANNER, phase=0.0)
    assert after.plain == before.plain
    assert after.spans == before.spans


def test_gradient_text_phase_shifts_colors():
    base = theme.gradient_text(theme.BANNER)
    shifted = theme.gradient_text(theme.BANNER, phase=0.5)
    first_color = next(
        s.style for s in base.spans if s.style
    )
    shifted_color = next(
        s.style for s in shifted.spans if s.style
    )
    assert shifted_color != first_color


def test_gradient_text_full_phase_cycle_returns_to_start():
    start = theme.gradient_text(theme.BANNER, phase=0.0)
    wrapped = theme.gradient_text(theme.BANNER, phase=1.0)
    assert wrapped.plain == start.plain
    assert wrapped.spans == start.spans
