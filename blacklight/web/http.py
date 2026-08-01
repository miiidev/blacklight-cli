"""Thin requests wrapper — the single mock point for web-scan tests."""

from dataclasses import dataclass

import requests

BROWSER_HEADERS = {
    "User-Agent": "blacklight-cli/0.1.0 web scanner",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}


@dataclass
class Page:
    """Fetched page: final URL, status, headers, decoded text."""

    url: str
    status: int
    headers: dict
    text: str

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


@dataclass
class ProbeResult:
    """Response to a crafted GET request."""

    status: int
    text: str


def fetch_page(url: str, timeout: int = 30) -> Page:
    """GET a page and return it as a Page (raises requests exceptions)."""
    resp = requests.get(url, headers=BROWSER_HEADERS, timeout=timeout)
    resp.raise_for_status()
    return Page(url=resp.url, status=resp.status_code,
                headers=dict(resp.headers), text=resp.text)


def probe(url: str, params: dict | None = None, timeout: int = 30) -> ProbeResult:
    """GET with optional query params; returns status + text."""
    resp = requests.get(url, params=params, headers=BROWSER_HEADERS, timeout=timeout)
    return ProbeResult(status=resp.status_code, text=resp.text)
