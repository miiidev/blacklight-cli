"""Web check registry: passive, error-based checks over a fetched page."""

from collections.abc import Callable

from blacklight.web.http import Page, ProbeResult
from blacklight.web.models import WebFinding

ProbeFn = Callable[[str, dict | None], ProbeResult]
Check = Callable[[Page, ProbeFn], WebFinding | None]

CHECKS: dict[str, Check] = {}


def _missing_header(name: str) -> Check:
    def check(page: Page, probe: ProbeFn) -> WebFinding | None:
        if page.header(name) is None:
            return WebFinding(
                url=page.url, category="security_header",
                detail=f"Missing {name} header", severity="low", evidence="",
            )
        return None

    return check


def _hsts_check(page: Page, probe: ProbeFn) -> WebFinding | None:
    if page.url.startswith("https://") and page.header("Strict-Transport-Security") is None:
        return WebFinding(
            url=page.url, category="security_header",
            detail="Missing Strict-Transport-Security header (HTTPS only)",
            severity="low", evidence="",
        )
    return None


CHECKS["header-x-frame-options"] = _missing_header("X-Frame-Options")
CHECKS["header-csp"] = _missing_header("Content-Security-Policy")
CHECKS["header-hsts"] = _hsts_check
CHECKS["header-x-content-type-options"] = _missing_header("X-Content-Type-Options")
CHECKS["header-referrer-policy"] = _missing_header("Referrer-Policy")
CHECKS["header-permissions-policy"] = _missing_header("Permissions-Policy")


from urllib.parse import urljoin, urlparse

import re

_DEFAULT_PAGE_MARKERS = (
    "Apache2 Ubuntu Default Page",
    "Welcome to nginx!",
    "Test Page for the Installation of the Internet Information Services",
)


def same_origin_links(page: Page) -> list[str]:
    """Absolute URLs of same-origin <a href>/<link href> links, deduped."""
    parsed = urlparse(page.url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    urls: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r'<(?:a|link)\s+[^>]*href=["\']([^"\']+)["\']', page.text):
        href = match.group(1)
        absolute = urljoin(page.url, href)
        if urlparse(absolute).netloc != parsed.netloc:
            continue
        if absolute not in seen:
            seen.add(absolute)
            urls.append(absolute)
    return urls


def _exposed_check(path: str, marker: str | None, severity: str, detail: str) -> Check:
    def check(page: Page, probe: ProbeFn) -> WebFinding | None:
        result = probe(urljoin(page.url, path))
        if result.status != 200:
            return None
        if marker is not None and marker not in result.text:
            return None
        return WebFinding(url=page.url, category="exposed_file",
                          detail=detail, severity=severity,
                          evidence=result.text.strip()[:200])

    return check


def _server_status_check(page: Page, probe: ProbeFn) -> WebFinding | None:
    return _exposed_check("/server-status", "Apache Server Status",
                          "medium", "Apache server-status page exposed")(page, probe)


def _wp_admin_check(page: Page, probe: ProbeFn) -> WebFinding | None:
    return _exposed_check("/wp-admin/", "wp-admin", "medium",
                          "WordPress admin (wp-admin) exposed")(page, probe)


def _backup_check(page: Page, probe: ProbeFn) -> WebFinding | None:
    for link in same_origin_links(page):
        path = urlparse(link).path
        if not path.endswith(".php"):
            continue
        result = probe(urljoin(page.url, path + ".bak"))
        if result.status == 200:
            return WebFinding(
                url=page.url, category="exposed_file",
                detail=f"Backup file exposed: {path}.bak",
                severity="medium", evidence=result.text.strip()[:200],
            )
    return None


def _dir_listing_check(page: Page, probe: ProbeFn) -> WebFinding | None:
    if "Index of /" in page.text:
        return WebFinding(url=page.url, category="misconfiguration",
                          detail="Directory listing enabled", severity="medium",
                          evidence="")
    return None


def _default_page_check(page: Page, probe: ProbeFn) -> WebFinding | None:
    for marker in _DEFAULT_PAGE_MARKERS:
        if marker in page.text:
            return WebFinding(url=page.url, category="misconfiguration",
                              detail="Default installation page exposed",
                              severity="medium", evidence=marker)
    return None


CHECKS["exposed-git-config"] = _exposed_check(
    "/.git/config", "[core]", "high", "Git repository config exposed (.git/config)")
CHECKS["exposed-env"] = _exposed_check(
    "/.env", "=", "high", "Environment file exposed (.env)")
CHECKS["exposed-phpinfo"] = _exposed_check(
    "/phpinfo.php", "phpinfo()", "high", "PHP info page exposed (phpinfo.php)")
CHECKS["exposed-server-status"] = _server_status_check
CHECKS["exposed-admin"] = _exposed_check("/admin/", None, "medium", "Admin panel exposed (/admin/)")
CHECKS["exposed-login"] = _exposed_check("/login", None, "medium", "Login page exposed (/login)")
CHECKS["exposed-wp-admin"] = _wp_admin_check
CHECKS["exposed-backup"] = _backup_check
CHECKS["misconfig-dir-listing"] = _dir_listing_check
CHECKS["misconfig-default-page"] = _default_page_check
