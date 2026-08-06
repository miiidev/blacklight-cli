"""Visual identity for blacklight-cli: banner art, colors, and gauges."""

import os
from collections import ChainMap

from rich.console import Console
from rich.text import Text

PURPLE = "#8b5cf6"
CYAN = "#22d3ee"
ACCENT = "#f0abfc"
DIM = "#6b7280"

BANNER = """\
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗     ██╗ ██████╗ ██╗  ██╗████████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║     ██║██╔════╝ ██║  ██║╚══██╔══╝
██████╔╝██║     ███████║██║     █████╔╝ ██║     ██║██║  ███╗███████║   ██║
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║     ██║██║   ██║██╔══██║   ██║
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗███████╗██║╚██████╔╝██║  ██║   ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝"""

BANNER_WIDTH = max(len(line) for line in BANNER.splitlines())

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "white",
    "unknown": "dim",
}


def _lerp_hex(start: str, end: str, t: float) -> str:
    """Interpolate two hex colors; t in [0, 1]."""

    def channels(color: str) -> tuple[int, int, int]:
        raw = color.lstrip("#")
        return tuple(int(raw[i : i + 2], 16) for i in (0, 2, 4))

    a, b = channels(start), channels(end)
    rgb = tuple(round(x + (y - x) * t) for x, y in zip(a, b))
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def gradient_text(text: str) -> Text:
    """Render text with a purple-to-cyan gradient across its width."""
    lines = text.splitlines()
    if not lines:
        return Text()
    max_width = max(len(line) for line in lines)
    out = Text()
    for i, line in enumerate(lines):
        for col, ch in enumerate(line):
            if ch == " ":
                out.append(" ")
            else:
                t = col / max(max_width - 1, 1)
                out.append(ch, style=_lerp_hex(PURPLE, CYAN, t))
        if i < len(lines) - 1:
            out.append("\n")
    return out


def print_banner(console: Console) -> None:
    """Print the gradient banner; skip silently when the console is narrow."""
    if console.width < BANNER_WIDTH:
        return
    console.print(gradient_text(BANNER))


def risk_gauge(score: float) -> str:
    """Ten-segment colored meter with the numeric score.

    Band colors: <30 green, <60 yellow, <80 dark_orange, else red.
    Score is clamped to [0, 100]; fill count rounds half-up.
    """
    clamped = max(0.0, min(100.0, score))
    filled = int(clamped / 10 + 0.5)
    if clamped < 30:
        color = "green"
    elif clamped < 60:
        color = "yellow"
    elif clamped < 80:
        color = "dark_orange"
    else:
        color = "red"
    bar = "█" * filled + "░" * (10 - filled)
    return f"[{color}]{bar}[/] {clamped:.1f}"


def enable_windows_vt() -> bool:
    """Enable ANSI Virtual Terminal Processing on Windows consoles.

    Without this, Windows consoles (cmd.exe, PowerShell, conhost) print
    ANSI escape sequences literally as '?[38;2;...' instead of rendering
    colors. Returns True when at least one handled stream is a console with
    VT applied, False otherwise (redirected pipe, non-console PTY, or
    non-Windows platforms where ANSI is universally supported).
    """
    if os.name != "nt":
        return True
    try:
        import ctypes
    except ImportError:
        return False
    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
    enabled = False
    for handle_id in (-11, -12):  # stdout, stderr
        handle = ctypes.windll.kernel32.GetStdHandle(handle_id)
        if not handle or handle == -1:
            continue
        mode = ctypes.c_uint32()
        if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            continue
        if ctypes.windll.kernel32.SetConsoleMode(
            handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        ):
            enabled = True
    return enabled


def make_console(color: bool = False, **kwargs: object) -> Console:
    """Build a rich Console that prints plain text by default.

    Plain output (no colors, no live cursor animation) is the default so
    blacklight never prints raw ANSI escapes on a display that cannot render
    them. Pass ``color=True`` to opt into full color and animated progress.
    NO_COLOR always wins and forces plain output. The TERM=dumb marker is
    what stops rich's Live widgets (progress bars) from emitting
    cursor-control escapes on the plain path.
    """
    if color and not os.environ.get("NO_COLOR"):
        return Console(**kwargs)
    environ = ChainMap({"TERM": "dumb"}, os.environ)
    kwargs.setdefault("_environ", environ)
    return Console(no_color=True, **kwargs)
