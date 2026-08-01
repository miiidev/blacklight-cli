"""Detect server/framework versions from headers and page markers."""

import re
from dataclasses import dataclass

from blacklight.web.http import Page

_SERVER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)(?:/([0-9][0-9.]*))?")
_POWERED_BY_RE = re.compile(r"([A-Za-z][A-Za-z0-9-]*)/([0-9][0-9.]*)")
_WP_VERSION_RE = re.compile(r'content="WordPress\s+([0-9][0-9.]*)"')
_PMA_VERSION_RE = re.compile(r"phpMyAdmin\s+([0-9][0-9.]*)")

_SERVER_SERVICE = {
    "apache": "apache httpd",
    "nginx": "nginx",
    "microsoft-iis": "iis",
    "tomcat": "apache tomcat",
}


@dataclass
class Fingerprint:
    """A detected tech: service key matching cpe_map.SERVICE_CPE + version."""

    service: str
    version: str


def _version_from_header(value: str, regex: re.Pattern) -> tuple[str, str] | None:
    match = regex.match(value)
    if match is None:
        return None
    name, version = match.group(1), match.group(2) or ""
    return name, version


def fingerprint_page(page: Page) -> list[Fingerprint]:
    """Extract tech fingerprints from a fetched page."""
    fingerprints: list[Fingerprint] = []
    server = page.header("Server")
    if server:
        hit = _version_from_header(server, _SERVER_RE)
        if hit:
            name, version = hit
            service = _SERVER_SERVICE.get(name.lower())
            if service is not None:
                fingerprints.append(Fingerprint(service, version))
    powered = page.header("X-Powered-By")
    if powered:
        hit = _version_from_header(powered, _POWERED_BY_RE)
        if hit:
            name, version = hit
            if name.lower() == "php":
                fingerprints.append(Fingerprint("php", version))
    wp = _WP_VERSION_RE.search(page.text)
    if wp is not None:
        fingerprints.append(Fingerprint("wordpress", wp.group(1)))
    pma = _PMA_VERSION_RE.search(page.text)
    if pma is not None:
        fingerprints.append(Fingerprint("phpmyadmin", pma.group(1)))
    return fingerprints
