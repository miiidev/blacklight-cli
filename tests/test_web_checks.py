from blacklight.web.checks import CHECKS
from blacklight.web.http import Page
from blacklight.web.models import WebFinding


def _page(url="http://example.com/", headers=None, text=""):
    return Page(url=url, status=200, headers=headers or {}, text=text)


def test_chains_registry_has_six_security_headers():
    names = {n for n, c in CHECKS.items() if n.startswith("header-")}
    assert names == {"header-x-frame-options", "header-csp", "header-hsts",
                     "header-x-content-type-options", "header-referrer-policy",
                     "header-permissions-policy"}


def test_missing_header_reported_low():
    page = _page(headers={"Server": "Apache"})
    finding = CHECKS["header-x-frame-options"](page, lambda *a, **k: None)
    assert isinstance(finding, WebFinding)
    assert finding.category == "security_header"
    assert finding.severity == "low"
    assert "X-Frame-Options" in finding.detail


def test_present_header_not_reported():
    page = _page(headers={"X-Frame-Options": "DENY",
                          "Content-Security-Policy": "default-src 'self'",
                          "Strict-Transport-Security": "max-age=31536000",
                          "X-Content-Type-Options": "nosniff",
                          "Referrer-Policy": "no-referrer",
                          "Permissions-Policy": "geolocation=()"})
    for name, check in CHECKS.items():
        if name.startswith("header-"):
            assert check(page, lambda *a, **k: None) is None


def test_hsts_only_checked_on_https():
    http_page = _page(url="http://example.com/", headers={})
    https_page = _page(url="https://example.com/", headers={})
    assert CHECKS["header-hsts"](http_page, lambda *a, **k: None) is None
    assert CHECKS["header-hsts"](https_page, lambda *a, **k: None) is not None
