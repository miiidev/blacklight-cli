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
