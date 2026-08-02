"""Visual identity for blacklight-cli: banner art, colors, and gauges."""

from rich.console import Console
from rich.text import Text

PURPLE = "#8b5cf6"
CYAN = "#22d3ee"
ACCENT = "#f0abfc"
DIM = "#6b7280"

BANNER = """\
         ▄▄▄▄▄▄▄▄▄▄
        ▐████████████▌
        ▐█ ▄▄█▀▀█▄▄ █▌
         ▀▀▀▀▀▀▀▀▀▀▀▀
███ █    █   ██ █ █ █   ███  ██ █ █ ███
█ █ █  █ █ █   █ █ █ █    █ █   █ █ █ █  █
███ █  ███ █   ██  █    █  █ ██ ███  █
█ █ █  █ █ █   █ █ █ █    █  █ █ █ █  █
███ ███ █ █  ██ █ █ ███ ███  ██ █ █  █
       scan · find · illuminate"""

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
    if console.width < 70:
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