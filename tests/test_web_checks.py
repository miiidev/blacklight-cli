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


from urllib.parse import urljoin


def _probe_with(responses):
    """Return a ProbeFn serving {path: (status, text)} from a base URL."""
    base = "http://example.com"

    def probe(url, params=None):
        key = url.replace(base, "")
        status, text = responses.get(key, (404, "not found"))
        return type("ProbeResult", (), {"status": status, "text": text})()

    return probe


def test_exposed_git_config_high():
    page = _page()
    probe = _probe_with({"/.git/config": (200, "[core]\n\trepositoryformatversion = 0")})
    finding = CHECKS["exposed-git-config"](page, probe)
    assert finding is not None
    assert finding.severity == "high"
    assert finding.category == "exposed_file"


def test_exposed_env_high():
    page = _page()
    probe = _probe_with({"/.env": (200, "APP_KEY=secret\nDB_PASSWORD=password")})
    finding = CHECKS["exposed-env"](page, probe)
    assert finding is not None
    assert finding.severity == "high"


def test_exposed_phpinfo_high():
    page = _page()
    probe = _probe_with({"/phpinfo.php": (200, "<h1>PHP Version 7.4.33</h1> phpinfo()")})
    finding = CHECKS["exposed-phpinfo"](page, probe)
    assert finding is not None
    assert "phpinfo" in finding.detail.lower()


def test_server_status_medium():
    page = _page()
    probe = _probe_with({"/server-status": (200, "<h1>Apache Server Status</h1>")})
    finding = CHECKS["exposed-server-status"](page, probe)
    assert finding is not None
    assert finding.severity == "medium"


def test_admin_and_login_medium():
    page = _page()
    admin_probe = _probe_with({"/admin/": (200, "<title>Admin</title>")})
    login_probe = _probe_with({"/login": (200, "<form>Password</form>")})
    assert CHECKS["exposed-admin"](page, admin_probe).severity == "medium"
    assert CHECKS["exposed-login"](page, login_probe).severity == "medium"


def test_wp_admin_medium():
    page = _page(text='<link href="/wp-content/theme.css">')
    probe = _probe_with({"/wp-admin/": (200, '<title>WordPress &rsaquo; Log In</title><link href="/wp-admin/css/login.css">')})
    finding = CHECKS["exposed-wp-admin"](page, probe)
    assert finding is not None
    assert finding.severity == "medium"


def test_backup_file_of_php_link_medium():
    page = _page(text='<a href="/index.php">Home</a>')
    probe = _probe_with({"/index.php.bak": (200, "<?php $db = new mysqli(")})
    finding = CHECKS["exposed-backup"](page, probe)
    assert finding is not None
    assert ".bak" in finding.detail
    assert finding.severity == "medium"


def test_no_backup_finding_without_links():
    page = _page(text="no links here")
    assert CHECKS["exposed-backup"](page, lambda *a, **k: None) is None


def test_directory_listing_medium():
    page = _page(text="<title>Index of /uploads</title>\nIndex of /uploads")
    finding = CHECKS["misconfig-dir-listing"](page, lambda *a, **k: None)
    assert finding is not None
    assert finding.severity == "medium"


def test_default_page_medium():
    page = _page(text="Welcome to nginx!\nIf you see this page, the nginx web server is successfully installed")
    finding = CHECKS["misconfig-default-page"](page, lambda *a, **k: None)
    assert finding is not None
    assert finding.severity == "medium"


def test_healthy_page_no_exposed_findings():
    page = _page(text="<html><body>Hello</body></html>")
    probe = _probe_with({})
    for name in ("exposed-git-config", "exposed-env", "exposed-phpinfo",
                 "exposed-server-status", "exposed-admin", "exposed-login",
                 "exposed-wp-admin", "exposed-backup"):
        assert CHECKS[name](page, probe) is None
