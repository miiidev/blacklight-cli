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
