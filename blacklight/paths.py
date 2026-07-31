"""Filesystem locations for blacklight state (cache, scan log)."""

from pathlib import Path

HOME_DIR = Path.home() / ".blacklight"
CACHE_DIR = HOME_DIR / "cache"
SCAN_LOG = HOME_DIR / "scan.log"


def ensure_dirs() -> None:
    """Create ~/.blacklight and ~/.blacklight/cache if missing."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
