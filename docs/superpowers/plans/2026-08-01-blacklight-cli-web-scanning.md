# blacklight-cli Web Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `blacklight web <url>` subcommand that passively probes web apps (security headers, exposed files/misconfigs, error-based SQLi/XSS/command injection on GET params) and fingerprints tech versions into the existing CPE → NVD pipeline.

**Architecture:** A new `blacklight/web/` subpackage (models, http, checks, fingerprint, engine) feeds a new `WebFinding` dataclass into the existing guardrails, NVD client, scoring, reporter, and scan-log infrastructure. Checks are a registry of small pure-ish functions `(Page, ProbeFn) -> WebFinding | None`; the engine runs them in isolation and converts fingerprint CVEs into WebFindings. All network I/O funnels through `web/http.py` — the single mock point for tests.

**Tech Stack:** Python 3.11+, `requests` (existing), `typer`/`rich`/`jinja2` (existing), stdlib `urllib.parse`, `socket`, `re`, `ipaddress`. **No new dependencies.**

## Global Constraints

- Python >= 3.11; package name `blacklight-cli`, command `blacklight` (pyproject unchanged).
- Deterministic, local, no LLM, no blind/time-based/out-of-band techniques, no exploitation, error-based detection only.
- No POST form probing; no recursive crawling beyond the homepage links; max 10 fuzzed params per page.
- All tests network-free: HTTP fakes via the `blacklight.web.http` module; DNS via monkeypatched `socket.getaddrinfo`; NVD via fake `NvdClient`.
- Severity vocabulary is exactly `critical|high|medium|low|unknown` (shared with `scoring.SEVERITY_WEIGHTS` and `reporter.SEVERITY_STYLE`).
- Every task: TDD — failing test first (RED), then implementation (GREEN), then commit. Full suite must stay green (68 existing tests).
- Existing modules (`cve_matcher`, `enrichment`, `scoring`, `reporter`, `guardrails`, `cpe_map`) keep their current public signatures; changes must be backward-compatible.
- Check failures never abort a run: the engine catches per-check exceptions and counts them in meta `checks_errored`.
- Graceful degradation: upstream failures print `Web scan failed: <reason>` + exit 1, never a traceback.
- Repo-local git identity is configured. Shell is Windows PowerShell (`;` not `&&`).

---

### Task 1: Web finding model + HTTP wrapper

**Files:**
- Create: `blacklight/web/__init__.py`
- Create: `blacklight/web/models.py`
- Create: `blacklight/web/http.py`
- Test: `tests/test_web_models.py`, `tests/test_web_http.py`

**Interfaces:**
- Consumes: `requests` library only.
- Produces: `WebFinding` dataclass (all later tasks), `Page.header(name)`, `fetch_page(url, timeout=30) -> Page`, `probe(url, params=None, timeout=30) -> ProbeResult` (engine/checks/CLI tests monkeypatch the module functions via `blacklight.web.engine.http.fetch_page` etc., so engine must call them through the module reference, and checks receive the probe callable from the engine).

- [ ] **Step 1: Write the failing tests**

`tests/test_web_models.py`:
```python
from blacklight.web.models import WebFinding


def test_web_finding_defaults():
    f = WebFinding(url="http://example.com/", category="security_header",
                   detail="Missing X-Frame-Options", severity="low", evidence="")
    assert f.cve_id == ""
    assert f.epss is None
    assert f.in_kev is False


def test_web_finding_to_dict():
    f = WebFinding(url="http://example.com/", category="sqli",
                   detail="SQL error", severity="high", evidence="SQL syntax",
                   cve_id="CVE-2024-0001", epss=0.95, in_kev=True)
    d = f.to_dict()
    assert d["type"] == "web"
    assert d["cve_id"] == "CVE-2024-0001"
    assert d["epss"] == 0.95
    assert d["in_kev"] is True
    assert d["url"] == "http://example.com/"
```

`tests/test_web_http.py`:
```python
import requests

from blacklight.web.http import Page, ProbeResult, fetch_page, probe


def test_page_header_is_case_insensitive():
    page = Page(url="http://example.com/", status=200,
                headers={"X-Frame-Options": "DENY", "Server": "Apache"}, text="")
    assert page.header("x-frame-options") == "DENY"
    assert page.header("SERVER") == "Apache"
    assert page.header("Missing") is None


def test_fetch_page_parses_response(monkeypatch):
    class FakeResp:
        url = "http://example.com/"
        status_code = 200
        headers = {"Server": "Apache/2.4.49"}
        text = "<html>hi</html>"

        def raise_for_status(self):
            pass

    monkeypatch.setattr("blacklight.web.http.requests.get",
                        lambda *a, **k: FakeResp())
    page = fetch_page("http://example.com/")
    assert page.status == 200
    assert page.text == "<html>hi</html>"
    assert page.header("server") == "Apache/2.4.49"


def test_probe_passes_params(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200
        text = "hello"

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["params"] = kwargs.get("params")
        return FakeResp()

    monkeypatch.setattr("blacklight.web.http.requests.get", fake_get)
    result = probe("http://example.com/search", params={"q": "x"})
    assert isinstance(result, ProbeResult)
    assert result.status == 200
    assert result.text == "hello"
    assert captured["url"] == "http://example.com/search"
    assert captured["params"] == {"q": "x"}


def test_fetch_page_raises_on_http_error(monkeypatch):
    class FakeResp:
        def raise_for_status(self):
            raise requests.HTTPError("404")

    monkeypatch.setattr("blacklight.web.http.requests.get",
                        lambda *a, **k: FakeResp())
    try:
        fetch_page("http://example.com/missing")
    except requests.HTTPError:
        return
    raise AssertionError("expected HTTPError")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_web_models.py tests/test_web_http.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'blacklight.web'`

- [ ] **Step 3: Write the implementation**

`blacklight/web/__init__.py`:
```python
"""Web application scanning: passive, error-based checks."""
```

`blacklight/web/models.py`:
```python
"""Web scanning findings: config bugs and fingerprint-backed CVEs."""

from dataclasses import dataclass


@dataclass
class WebFinding:
    """A single web check result or fingerprint CVE finding."""

    url: str
    category: str
    detail: str
    severity: str
    evidence: str
    cve_id: str = ""
    epss: float | None = None
    in_kev: bool = False

    def to_dict(self) -> dict:
        return {
            "type": "web",
            "url": self.url,
            "category": self.category,
            "detail": self.detail,
            "severity": self.severity,
            "evidence": self.evidence,
            "cve_id": self.cve_id,
            "epss": self.epss,
            "in_kev": self.in_kev,
        }
```

`blacklight/web/http.py`:
```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_web_models.py tests/test_web_http.py -q`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add blacklight/web/__init__.py blacklight/web/models.py blacklight/web/http.py tests/test_web_models.py tests/test_web_http.py
git commit -m "feat: add web finding model and HTTP wrapper"
```

---

### Task 2: Web target guardrails

**Files:**
- Modify: `blacklight/guardrails.py` (append three functions)
- Test: `tests/test_web_guardrails.py`

**Interfaces:**
- Consumes: existing `guardrails.Verdict`, `guardrails.is_private(target) -> bool` (signature unchanged).
- Produces: `guardrails.normalize_web_url(url: str) -> str` (bare hostname gets `https://`), `guardrails.resolve_hostname(hostname: str) -> str | None` (first IPv4 from `socket.getaddrinfo`, None on failure), `guardrails.verify_web_target(url: str, permission_granted: bool) -> Verdict` (single URL classified: `allowed` = private; `needs_confirmation` = public with permission granted; `blocked` = invalid scheme, no hostname, unresolvable, or public without permission). The CLI (Task 10) and engine (Task 8) consume these.

- [ ] **Step 1: Write the failing tests**

`tests/test_web_guardrails.py`:
```python
from blacklight.guardrails import normalize_web_url, resolve_hostname, verify_web_target


def test_normalize_web_url_adds_https():
    assert normalize_web_url("example.com") == "https://example.com"
    assert normalize_web_url("http://example.com") == "http://example.com"
    assert normalize_web_url("https://example.com:8080") == "https://example.com:8080"


def test_resolve_hostname_returns_ipv4(monkeypatch):
    fake = [("AF_INET", 1, 6, "", ("192.168.1.10", 0)),
            ("AF_INET6", 10, 6, "", ("::1", 0, 0, 0))]
    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: fake)
    assert resolve_hostname("myhost") == "192.168.1.10"


def test_resolve_hostname_returns_none_on_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("name or service not known")

    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo", boom)
    assert resolve_hostname("does-not-exist.invalid") is None


def test_verify_web_target_private_allowed(monkeypatch):
    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("127.0.0.1", 0))])
    verdict = verify_web_target("http://127.0.0.1:8080", False)
    assert verdict.allowed == ["http://127.0.0.1:8080"]
    assert verdict.needs_confirmation == []
    assert verdict.blocked == []


def test_verify_web_target_public_without_permission_blocked(monkeypatch):
    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("8.8.8.8", 0))])
    verdict = verify_web_target("https://example.com", False)
    assert verdict.blocked == ["https://example.com"]
    assert verdict.allowed == []


def test_verify_web_target_public_with_permission_needs_confirmation(monkeypatch):
    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("8.8.8.8", 0))])
    verdict = verify_web_target("https://example.com", True)
    assert verdict.needs_confirmation == ["https://example.com"]


def test_verify_web_target_rejects_bad_scheme():
    verdict = verify_web_target("ftp://example.com", True)
    assert verdict.blocked == ["ftp://example.com"]


def test_verify_web_target_rejects_unresolvable(monkeypatch):
    def boom(*a, **k):
        raise OSError("no such host")

    monkeypatch.setattr("blacklight.guardrails.socket.getaddrinfo", boom)
    verdict = verify_web_target("https://does-not-exist.invalid", True)
    assert verdict.blocked == ["https://does-not-exist.invalid"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_web_guardrails.py -q`
Expected: FAIL — `ImportError: cannot import name 'normalize_web_url'`

- [ ] **Step 3: Write the implementation**

Append to `blacklight/guardrails.py`:
```python
import socket
import urllib.parse
```
(add to the existing imports at the top), then at the end of the file:
```python
def normalize_web_url(url: str) -> str:
    """Prefix https:// when the input has no scheme."""
    url = url.strip()
    if not urllib.parse.urlparse(url).scheme:
        return "https://" + url
    return url


def resolve_hostname(hostname: str) -> str | None:
    """Resolve a hostname to its first IPv4 address, or None on failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return None
    for info in infos:
        ip = info[4][0]
        if ":" not in ip:
            return ip
    return None


def verify_web_target(url: str, permission_granted: bool) -> Verdict:
    """Classify a web target URL: allowed / needs_confirmation / blocked."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return Verdict(allowed=[], needs_confirmation=[], blocked=[url])
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return Verdict(allowed=[], needs_confirmation=[], blocked=[url])
    ip = resolve_hostname(parsed.hostname)
    if ip is None:
        return Verdict(allowed=[], needs_confirmation=[], blocked=[url])
    if is_private(ip):
        return Verdict(allowed=[url], needs_confirmation=[], blocked=[])
    if permission_granted:
        return Verdict(allowed=[], needs_confirmation=[url], blocked=[])
    return Verdict(allowed=[], needs_confirmation=[], blocked=[url])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_web_guardrails.py -q`
Expected: 8 passed. Then run `python -m pytest -q` — full suite still green (68 + 8).

- [ ] **Step 5: Commit**

```bash
git add blacklight/guardrails.py tests/test_web_guardrails.py
git commit -m "feat: add web target guardrails with hostname resolution"
```

---

### Task 3: Check registry + security header checks

**Files:**
- Create: `blacklight/web/checks.py`
- Test: `tests/test_web_checks.py`

**Interfaces:**
- Consumes: `blacklight.web.models.WebFinding`, `blacklight.web.http.Page`.
- Produces: `Check = Callable[[Page, Callable[[str, dict | None], ProbeResult]], WebFinding | None]` (type alias), `CHECKS: dict[str, Check]` (name → check; engine iterates it and reports `len(CHECKS)` as checks_run), the six header checks. The probe callable signature is `probe(url: str, params: dict | None = None) -> ProbeResult`.

- [ ] **Step 1: Write the failing tests**

`tests/test_web_checks.py`:
```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_web_checks.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'blacklight.web.checks'`

- [ ] **Step 3: Write the implementation**

`blacklight/web/checks.py`:
```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_web_checks.py -q`
Expected: 4 passed. Then `python -m pytest -q` full suite green.

- [ ] **Step 5: Commit**

```bash
git add blacklight/web/checks.py tests/test_web_checks.py
git commit -m "feat: add web check registry with security header checks"
```

---

### Task 4: Exposed files & misconfiguration checks

**Files:**
- Modify: `blacklight/web/checks.py` (append checks + `same_origin_links` helper)
- Test: `tests/test_web_checks.py` (append tests)

**Interfaces:**
- Consumes: Task 3's `CHECKS`, `Check`, `ProbeFn`, `WebFinding`, `Page`.
- Produces: `checks.same_origin_links(page: Page) -> list[str]` (absolute URLs of same-origin links in the page, deduped, `<a href>` and `<link href>`; Task 5 uses it for params), and nine new registry entries: `exposed-git-config`, `exposed-env`, `exposed-phpinfo`, `exposed-server-status`, `exposed-admin`, `exposed-login`, `exposed-wp-admin`, `exposed-backup`, `misconfig-dir-listing`, `misconfig-default-page`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_web_checks.py`:
```python
from urllib.parse import urljoin


def _probe_with(responses):
    """Return a ProbeFn serving {path: (status, text)} from a base URL."""
    base = "http://example.com/"

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
    probe = _probe_with({"/wp-admin/": (200, "<title>WordPress &rsaquo; Log In</title>")})
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_web_checks.py -q`
Expected: FAIL — `KeyError: 'exposed-git-config'`

- [ ] **Step 3: Write the implementation**

Append to `blacklight/web/checks.py`:
```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_web_checks.py -q`
Expected: all pass (4 header + 12 new). Then `python -m pytest -q` full suite green.

- [ ] **Step 5: Commit**

```bash
git add blacklight/web/checks.py tests/test_web_checks.py
git commit -m "feat: add exposed file and misconfiguration checks"
```

---

### Task 5: Injection checks (SQLi, XSS, command injection)

**Files:**
- Modify: `blacklight/web/checks.py` (append helper + three checks)
- Test: `tests/test_web_checks.py` (append tests)

**Interfaces:**
- Consumes: Task 3 `Check`/`ProbeFn`, Task 4 `same_origin_links`, `WebFinding`, `Page`.
- Produces: `checks.link_params(page: Page, limit: int = 10) -> list[tuple[str, str]]` ((absolute url, param name) for same-origin links carrying query params, deduped, capped), and three registry entries: `sqli-get`, `xss-reflected`, `cmd-injection`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_web_checks.py`:
```python
from blacklight.web.checks import link_params


def test_link_params_discovers_query_params():
    page = _page(text='<a href="/search?q=hello&page=2">S</a> <a href="/search?q=hi">S2</a>')
    params = link_params(page, limit=10)
    assert ("http://example.com/search", "q") in params
    assert ("http://example.com/search", "page") in params
    assert len(params) == 2


def test_link_params_ignores_other_origins():
    page = _page(text='<a href="https://evil.example.com/x?a=1">X</a>')
    assert link_params(page) == []


def test_sqli_detected_on_error_signature():
    page = _page(text='<a href="/search?q=hello">S</a>')

    def probe(url, params=None):
        if "q=" in url and ("'" in url or "%27" in url):
            return type("P", (), {"status": 200,
                                  "text": "You have an error in your SQL syntax"})()
        return type("P", (), {"status": 200, "text": "normal page"})()

    finding = CHECKS["sqli-get"](page, probe)
    assert finding is not None
    assert finding.severity == "high"
    assert finding.category == "sqli"


def test_sqli_not_detected_on_clean_page():
    page = _page(text='<a href="/search?q=hello">S</a>')

    def probe(url, params=None):
        return type("P", (), {"status": 200, "text": "normal page"})()

    assert CHECKS["sqli-get"](page, probe) is None


def test_sqli_baseline_already_error_does_not_trigger():
    page = _page(text='<a href="/search?q=hello">S</a>')

    def probe(url, params=None):
        return type("P", (), {"status": 200, "text": "SQL syntax in everything"})

    assert CHECKS["sqli-get"](page, probe) is None


def test_xss_detected_on_reflection():
    page = _page(text='<a href="/search?q=hello">S</a>')

    def probe(url, params=None):
        if "svg" in url:
            return type("P", (), {"status": 200,
                                  "text": '<input value=""><svg/onload=alert(1)>">'})()
        return type("P", (), {"status": 200, "text": "normal page"})()

    finding = CHECKS["xss-reflected"](page, probe)
    assert finding is not None
    assert finding.severity == "medium"


def test_cmd_injection_detected_on_uid():
    page = _page(text='<a href="/ping?host=localhost">S</a>')

    def probe(url, params=None):
        if "id" in url:
            return type("P", (), {"status": 200,
                                  "text": "uid=0(root) gid=0(root)"})()
        return type("P", (), {"status": 200, "text": "ping output"})()

    finding = CHECKS["cmd-injection"](page, probe)
    assert finding is not None
    assert finding.severity == "high"


def test_cmd_injection_not_detected_clean():
    page = _page(text='<a href="/ping?host=localhost">S</a>')

    def probe(url, params=None):
        return type("P", (), {"status": 200, "text": "64 bytes from 127.0.0.1"})()

    assert CHECKS["cmd-injection"](page, probe) is None


def test_no_params_no_injection_checks():
    page = _page(text='<a href="/plain">P</a>')
    for name in ("sqli-get", "xss-reflected", "cmd-injection"):
        assert CHECKS[name](page, lambda *a, **k: None) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_web_checks.py -q`
Expected: FAIL — `KeyError: 'sqli-get'`

- [ ] **Step 3: Write the implementation**

Append to `blacklight/web/checks.py`:
```python
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SQL_SIGNATURES = re.compile(
    r"SQL syntax|mysql_fetch|ORA-[0-9]{5}|PostgreSQL.*ERROR|"
    r"Unclosed quotation mark|Microsoft OLE DB|SQLSTATE"
)
_CMD_SIGNATURES = re.compile(r"uid=\d+\(|command not found|sh: |/bin/sh")


def link_params(page: Page, limit: int = 10) -> list[tuple[str, str]]:
    """(absolute_url, param_name) pairs for same-origin links with query params."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for link in same_origin_links(page):
        parsed = urlsplit(link)
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
            pair = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}", key)
            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)
        if len(pairs) >= limit:
            break
    return pairs


def _replace_param(url: str, param: str, value: str) -> str:
    parsed = urlsplit(url)
    qs = [(key, value if key == param else val)
          for key, val in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       urlencode(qs), ""))


def _injection_check(category: str, severity: str, payloads: list[str],
                     trigger: re.Pattern, detail: str) -> Check:
    def check(page: Page, probe: ProbeFn) -> WebFinding | None:
        for url, param in link_params(page):
            baseline = probe(url)
            if baseline.status != 200 or trigger.search(baseline.text):
                continue
            for payload in payloads:
                result = probe(_replace_param(url, param, payload))
                if result.status == 200 and trigger.search(result.text):
                    return WebFinding(
                        url=page.url, category=category,
                        detail=f"{detail} in parameter '{param}'",
                        severity=severity,
                        evidence=result.text.strip()[:200],
                    )
        return None

    return check


CHECKS["sqli-get"] = _injection_check(
    "sqli", "high",
    ["'", "' OR 1=1 -- "],
    _SQL_SIGNATURES,
    "Possible SQL injection",
)
CHECKS["xss-reflected"] = _injection_check(
    "xss", "medium",
    ['"><svg/onload=alert(1)>'],
    re.compile(re.escape('"><svg/onload=alert(1)>')),
    "Reflected XSS payload",
)
CHECKS["cmd-injection"] = _injection_check(
    "cmd_injection", "high",
    [";id"],
    _CMD_SIGNATURES,
    "Possible OS command injection",
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_web_checks.py -q`
Expected: all pass. Then `python -m pytest -q` full suite green.

- [ ] **Step 5: Commit**

```bash
git add blacklight/web/checks.py tests/test_web_checks.py
git commit -m "feat: add error-based SQLi, XSS, and command injection checks"
```

---

### Task 6: Tech fingerprinting → CPE

**Files:**
- Create: `blacklight/web/fingerprint.py`
- Modify: `blacklight/cpe_map.py` (add `php` entry)
- Test: `tests/test_web_fingerprint.py`, modify `tests/test_cpe_map.py` (append php test)

**Interfaces:**
- Consumes: `blacklight.web.http.Page`; `cpe_map.SERVICE_CPE`; `cpe_map.service_to_cpe(service, version)` (unchanged).
- Produces: `fingerprint.Fingerprint(service: str, version: str)` dataclass, `fingerprint.fingerprint_page(page: Page) -> list[Fingerprint]` (service keys must match `SERVICE_CPE` keys: `apache httpd`, `nginx`, `iis`, `apache tomcat`, `php`, `wordpress`, `phpmyadmin`). Engine (Task 8) feeds these into `service_to_cpe` + `build_findings`.

- [ ] **Step 1: Write the failing tests**

`tests/test_web_fingerprint.py`:
```python
from blacklight.web.fingerprint import Fingerprint, fingerprint_page
from blacklight.web.http import Page


def _page(headers=None, text=""):
    return Page(url="https://example.com/", status=200, headers=headers or {}, text=text)


def test_apache_server_header():
    fps = fingerprint_page(_page(headers={"Server": "Apache/2.4.49 (Ubuntu)"}))
    assert Fingerprint("apache httpd", "2.4.49") in fps


def test_nginx_server_header():
    fps = fingerprint_page(_page(headers={"Server": "nginx/1.18.0"}))
    assert Fingerprint("nginx", "1.18.0") in fps


def test_iis_server_header():
    fps = fingerprint_page(_page(headers={"Server": "Microsoft-IIS/10.0"}))
    assert Fingerprint("iis", "10.0") in fps


def test_php_powered_by():
    fps = fingerprint_page(_page(headers={"X-Powered-By": "PHP/7.4.33"}))
    assert Fingerprint("php", "7.4.33") in fps


def test_unknown_server_skipped():
    fps = fingerprint_page(_page(headers={"Server": "Cowboy"}))
    assert all(f.service != "cowboy" for f in fps)


def test_wordpress_marker():
    text = '<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/x.css">'
    fps = fingerprint_page(_page(text=text))
    assert Fingerprint("wordpress", "6.4.2") in fps


def test_phpmyadmin_marker():
    fps = fingerprint_page(_page(text="phpMyAdmin 5.2.1 - Documentation"))
    assert Fingerprint("phpmyadmin", "5.2.1") in fps


def test_no_markers_no_fingerprints():
    assert fingerprint_page(_page(text="just a page")) == []


def test_server_without_version_has_empty_version():
    fps = fingerprint_page(_page(headers={"Server": "Apache"}))
    assert Fingerprint("apache httpd", "") in fps
```

Append to `tests/test_cpe_map.py`:
```python
def test_php_maps_to_php():
    assert "cpe:2.3:a:php:php:7.4.33:*:*:*:*:*:*:*" in (
        __import__("blacklight.cpe_map", fromlist=["service_to_cpe"]).service_to_cpe("php", "7.4.33")
    )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_web_fingerprint.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'blacklight.web.fingerprint'`

- [ ] **Step 3: Write the implementation**

`blacklight/web/fingerprint.py`:
```python
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
```

Add to `blacklight/cpe_map.py` SERVICE_CPE dict (alphabetical placement near postgres):
```python
    "php": ("php", "php"),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_web_fingerprint.py tests/test_cpe_map.py -q`
Expected: all pass. Then `python -m pytest -q` full suite green.

- [ ] **Step 5: Commit**

```bash
git add blacklight/web/fingerprint.py blacklight/cpe_map.py tests/test_web_fingerprint.py tests/test_cpe_map.py
git commit -m "feat: add tech fingerprinting with CPE mapping for php"
```

---

### Task 7: Web risk scoring

**Files:**
- Modify: `blacklight/scoring.py` (append `web_risk_score`)
- Test: `tests/test_scoring.py` (append tests)

**Interfaces:**
- Consumes: `scoring.SEVERITY_WEIGHTS` (unchanged), `blacklight.web.models.WebFinding`.
- Produces: `scoring.web_risk_score(findings: list[WebFinding]) -> float` — sum of severity weights, capped at 100, rounded to 1dp. Also hardens nothing in `host_risk_score` (it already treats `epss=None` as 0 via `f.epss or 0.0`) — the test below locks that behavior in.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_scoring.py`:
```python
from blacklight.scoring import web_risk_score
from blacklight.web.models import WebFinding


def test_web_risk_score_sums_severity_weights():
    findings = [
        WebFinding(url="u", category="sqli", detail="", severity="high", evidence=""),
        WebFinding(url="u", category="xss", detail="", severity="medium", evidence=""),
        WebFinding(url="u", category="security_header", detail="", severity="low", evidence=""),
    ]
    assert web_risk_score(findings) == 15.0  # 10 + 4 + 1


def test_web_risk_score_caps_at_100():
    findings = [
        WebFinding(url="u", category="sqli", detail="", severity="critical", evidence="")
        for _ in range(10)
    ]
    assert web_risk_score(findings) == 100.0


def test_web_risk_score_empty():
    assert web_risk_score([]) == 0.0


def test_host_risk_score_treats_none_epss_as_zero():
    f = Finding(host="h", port=80, service="s", version="v", cpe="c",
                cve_id="CVE-1", description="d", cvss_score=9.0,
                severity="critical", fixed_version=None, epss=None, in_kev=False)
    assert host_risk_score([f]) == 20.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_scoring.py -q`
Expected: FAIL — `ImportError: cannot import name 'web_risk_score'`

- [ ] **Step 3: Write the implementation**

Append to `blacklight/scoring.py`:
```python
from blacklight.web.models import WebFinding


def web_risk_score(findings: list[WebFinding]) -> float:
    """Score a web target 0-100 from its findings (severity weights only)."""
    base = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return round(min(base, 100), 1)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_scoring.py -q`
Expected: all pass. Then `python -m pytest -q` full suite green.

- [ ] **Step 5: Commit**

```bash
git add blacklight/scoring.py tests/test_scoring.py
git commit -m "feat: add web risk score and lock epss-none handling"
```

---

### Task 8: Web scan engine

**Files:**
- Create: `blacklight/web/engine.py`
- Test: `tests/test_web_engine.py`

**Interfaces:**
- Consumes: `blacklight.web.http` module (call through module ref: `http.fetch_page`, `http.probe` — tests monkeypatch `blacklight.web.engine.http.*`), `blacklight.web.checks.CHECKS`, `blacklight.web.fingerprint.fingerprint_page`, `blacklight.web.models.WebFinding`, `blacklight.guardrails.resolve_hostname`, `blacklight.cve_matcher.{NvdClient, build_findings, Finding}`, `blacklight.enrichment.enrich_findings`, `blacklight.cpe_map.service_to_cpe`, `blacklight.scanner.ScanRecord`, `os.environ`.
- Produces: `engine.WebResult(findings: list[WebFinding], meta: dict)` dataclass; `engine.run_web_scan(url: str, timeout: int = 30, no_cache: bool = False) -> WebResult`. meta keys: `url, host, resolved_ip, checks_run, checks_errored, cve_findings, generated` (UTC ISO seconds). `engine.port_for_url(url) -> int` (explicit port, else 443 for https / 80 for http).

- [ ] **Step 1: Write the failing tests**

`tests/test_web_engine.py`:
```python
import os

from blacklight.cve_matcher import CVE, Finding
from blacklight.scanner import ScanRecord
from blacklight.web.engine import WebResult, port_for_url, run_web_scan


def _page(url="https://example.com/", status=200, headers=None, text="hello"):
    from blacklight.web.http import Page
    return Page(url=url, status=status, headers=headers or {}, text=text)


def test_port_for_url():
    assert port_for_url("http://example.com") == 80
    assert port_for_url("https://example.com") == 443
    assert port_for_url("https://example.com:8443") == 8443


def test_run_web_scan_runs_all_checks_and_meta(monkeypatch):
    page = _page(text='<a href="/search?q=x">S</a>', headers={"X-Frame-Options": "DENY"})
    monkeypatch.setattr("blacklight.web.engine.http.fetch_page", lambda *a, **k: page)
    monkeypatch.setattr("blacklight.web.engine.http.probe",
                        lambda url, params=None, **k: type("P", (), {"status": 200, "text": "ok"})())
    monkeypatch.setattr("blacklight.web.engine.guardrails.resolve_hostname",
                        lambda host: "192.168.1.10")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.web.engine.NvdClient", FakeClient)
    result = run_web_scan("https://example.com/")
    assert isinstance(result, WebResult)
    assert result.meta["url"] == "https://example.com/"
    assert result.meta["host"] == "example.com"
    assert result.meta["resolved_ip"] == "192.168.1.10"
    assert result.meta["checks_errored"] == 0
    assert result.meta["cve_findings"] == 0
    assert result.meta["checks_run"] > 0
    assert "generated" in result.meta


def test_run_web_scan_finds_header_and_other_findings(monkeypatch):
    page = _page(headers={})
    monkeypatch.setattr("blacklight.web.engine.http.fetch_page", lambda *a, **k: page)
    monkeypatch.setattr("blacklight.web.engine.http.probe",
                        lambda url, params=None, **k: type("P", (), {"status": 200, "text": "ok"})())
    monkeypatch.setattr("blacklight.web.engine.guardrails.resolve_hostname",
                        lambda host: "127.0.0.1")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.web.engine.NvdClient", FakeClient)
    result = run_web_scan("http://127.0.0.1/")
    categories = {f.category for f in result.findings}
    assert "security_header" in categories


def test_run_web_scan_counts_errored_checks(monkeypatch):
    all_headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    page = _page(headers=all_headers)
    monkeypatch.setattr("blacklight.web.engine.http.fetch_page", lambda *a, **k: page)
    monkeypatch.setattr("blacklight.web.engine.http.probe",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr("blacklight.web.engine.guardrails.resolve_hostname",
                        lambda host: "127.0.0.1")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.web.engine.NvdClient", FakeClient)
    result = run_web_scan("http://127.0.0.1/")
    assert result.meta["checks_errored"] > 0
    assert result.findings == []


def test_run_web_scan_builds_cve_findings_from_fingerprint(monkeypatch):
    page = _page(headers={"Server": "Apache/2.4.49"})
    monkeypatch.setattr("blacklight.web.engine.http.fetch_page", lambda *a, **k: page)
    monkeypatch.setattr("blacklight.web.engine.guardrails.resolve_hostname",
                        lambda host: "192.168.1.10")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            assert cpe.startswith("cpe:2.3:a:apache:http_server:2.4.49")
            return [CVE("CVE-2021-41773", "Path traversal", 9.8, "critical", "2.4.50")]

    monkeypatch.setattr("blacklight.web.engine.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.web.engine.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    result = run_web_scan("https://example.com/")
    cve_findings = [f for f in result.findings if f.category == "fingerprint"]
    assert len(cve_findings) == 1
    assert cve_findings[0].cve_id == "CVE-2021-41773"
    assert cve_findings[0].severity == "critical"
    assert cve_findings[0].evidence.startswith("cpe:2.3:a:apache")
    assert result.meta["cve_findings"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_web_engine.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'blacklight.web.engine'`

- [ ] **Step 3: Write the implementation**

`blacklight/web/engine.py`:
```python
"""Web scan orchestration: run checks + fingerprint CVEs into WebFindings."""

import os
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

from blacklight import enrichment, guardrails
from blacklight.cpe_map import service_to_cpe
from blacklight.cve_matcher import Finding, NvdClient, build_findings
from blacklight.scanner import ScanRecord
from blacklight.web import http
from blacklight.web.checks import CHECKS
from blacklight.web.fingerprint import Fingerprint, fingerprint_page
from blacklight.web.models import WebFinding


@dataclass
class WebResult:
    """Outcome of a web scan: findings plus run metadata."""

    findings: list[WebFinding]
    meta: dict


def port_for_url(url: str) -> int:
    """Default port for a URL: explicit port, else 443/80 by scheme."""
    parsed = urllib.parse.urlparse(url)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _hostname(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""


def _cve_findings(url: str, host: str, page: http.Page, no_cache: bool) -> list[WebFinding]:
    fingerprints = fingerprint_page(page)
    if not fingerprints:
        return []
    client = NvdClient(api_key=os.environ.get("BLACKLIGHT_NVD_KEY"), no_cache=no_cache)
    matched: list[Finding] = []
    for fp in fingerprints:
        cpe = service_to_cpe(fp.service, fp.version)
        if cpe is None:
            continue
        record = ScanRecord(host=host, port=port_for_url(url), protocol="tcp",
                            service=fp.service, version=fp.version)
        matched.extend(build_findings([record], client))
    enrichment.enrich_findings(matched)
    return [
        WebFinding(url=page.url, category="fingerprint", detail=f.description,
                   severity=f.severity, evidence=f.cpe,
                   cve_id=f.cve_id, epss=f.epss, in_kev=f.in_kev)
        for f in matched
    ]


def run_web_scan(url: str, timeout: int = 30, no_cache: bool = False) -> WebResult:
    """Fetch the page, run all checks, fingerprint CVEs, return findings + meta."""
    page = http.fetch_page(url, timeout)
    findings: list[WebFinding] = []
    errored = 0

    def probe(target_url: str, params: dict | None = None):
        return http.probe(target_url, params, timeout)

    for name, check in CHECKS.items():
        try:
            finding = check(page, probe)
        except Exception:
            errored += 1
            continue
        if finding is not None:
            findings.append(finding)

    host = _hostname(page.url)
    resolved = guardrails.resolve_hostname(host) or host
    findings.extend(_cve_findings(url, resolved, page, no_cache))
    meta = {
        "url": url,
        "host": host,
        "resolved_ip": resolved,
        "checks_run": len(CHECKS),
        "checks_errored": errored,
        "cve_findings": sum(1 for f in findings if f.category == "fingerprint"),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return WebResult(findings=findings, meta=meta)

Also update `blacklight/web/__init__.py` to re-export the engine (after engine.py exists, this import is safe — engine imports submodules, never the package root):
```python
"""Web application scanning: passive, error-based checks."""

from blacklight.web.engine import WebResult, run_web_scan

__all__ = ["WebResult", "run_web_scan"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_web_engine.py -q`
Expected: 5 passed. Then `python -m pytest -q` full suite green.

- [ ] **Step 5: Commit**

```bash
git add blacklight/web/engine.py blacklight/web/__init__.py tests/test_web_engine.py
git commit -m "feat: add web scan engine with fingerprint CVE pipeline"
```

---

### Task 9: Reporter web support

**Files:**
- Modify: `blacklight/reporter.py`
- Modify: `blacklight/templates/report.html.j2`, `blacklight/templates/report.md.j2`
- Test: `tests/test_reporter.py` (append tests)

**Interfaces:**
- Consumes: `blacklight.web.models.WebFinding`, `blacklight.scoring.web_risk_score`, existing `findings_table`/`host_risk_table` (unchanged).
- Produces (backward-compatible):
  - `render_terminal(findings, meta, console=None, web_findings=None, web_meta=None)` — new keyword args; existing network behavior identical when `web_findings is None`; when provided, prints a web summary panel + web findings table before the network sections.
  - `export_report(findings, meta, fmt, output, web_findings=None, web_meta=None)` — new keyword args; JSON gains a `"web"` key, templates gain a web section.
  - `web_findings_table(web_findings: list[WebFinding]) -> Table` (public, tested).
  - `_web_summary_text(web_findings, web_meta) -> str`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_reporter.py`:
```python
from blacklight.reporter import web_findings_table
from blacklight.web.models import WebFinding


def _web_findings():
    return [
        WebFinding(url="http://example.com/", category="security_header",
                   detail="Missing X-Frame-Options", severity="low", evidence=""),
        WebFinding(url="http://example.com/", category="sqli",
                   detail="Possible SQL injection in parameter 'q'",
                   severity="high", evidence="You have an error in your SQL syntax"),
    ]


def test_web_findings_table_columns():
    table = web_findings_table(_web_findings())
    assert table.title == "Web findings"
    assert [c.header for c in table.columns] == ["Category", "URL", "Severity", "Detail", "Evidence"]


def test_render_terminal_with_web_section():
    import io
    from rich.console import Console
    out = io.StringIO()
    render_terminal([], {}, Console(file=out), web_findings=_web_findings(),
                    web_meta={"url": "http://example.com/", "checks_run": 18,
                              "checks_errored": 0, "resolved_ip": "127.0.0.1",
                              "host": "example.com", "cve_findings": 0})
    text = out.getvalue()
    assert "web report" in text
    assert "Checks run: 18" in text
    assert "Web risk score: 11.0" in text
    assert "Possible SQL injection" in text


def test_render_terminal_without_web_section_unaffected():
    import io
    from rich.console import Console
    out = io.StringIO()
    render_terminal([], {"targets": "192.168.1.10", "hosts_scanned": 0,
                         "services_found": 0, "findings_count": 0}, Console(file=out))
    text = out.getvalue()
    assert "Web risk score" not in text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_reporter.py -q`
Expected: FAIL — `ImportError: cannot import name 'web_findings_table'`

- [ ] **Step 3: Write the implementation**

Modify `blacklight/reporter.py`:

Imports — add:
```python
from blacklight.scoring import host_risk_score, web_risk_score
from blacklight.web.models import WebFinding
```

Add functions after `host_risk_table`:
```python
def web_findings_table(web_findings: list[WebFinding]) -> Table:
    """Rich table of web findings grouped by severity."""
    table = Table(title="Web findings", expand=True)
    table.add_column("Category")
    table.add_column("URL")
    table.add_column("Severity")
    table.add_column("Detail")
    table.add_column("Evidence")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    for finding in sorted(web_findings, key=lambda f: order.get(f.severity, 4)):
        detail = finding.detail
        evidence = finding.evidence
        if finding.cve_id:
            detail = f"{finding.cve_id}: {detail}"
            kev = " [red]KEV[/red]" if finding.in_kev else ""
            epss = f"{finding.epss:.3f}" if finding.epss is not None else "-"
            evidence = f"{evidence} (EPSS {epss}{kev})"
        table.add_row(
            finding.category, finding.url, finding.severity, detail, evidence,
            style=SEVERITY_STYLE.get(finding.severity, ""),
        )
    return table


def _web_summary_text(web_findings: list[WebFinding], web_meta: dict) -> str:
    return (
        f"[bold]blacklight-cli[/] v{__version__} - web report\n"
        f"URL: [bold]{web_meta['url']}[/] ({web_meta['resolved_ip']}) | "
        f"Checks run: {web_meta['checks_run']} | Checks errored: {web_meta['checks_errored']} | "
        f"Web findings: {len(web_findings)} | Web risk score: {web_risk_score(web_findings)}"
    )
```

Modify `render_terminal` signature and body:
```python
def render_terminal(
    findings: list[Finding],
    meta: dict,
    console: Console | None = None,
    web_findings: list[WebFinding] | None = None,
    web_meta: dict | None = None,
) -> None:
    """Render the rich terminal report."""
    console = console or Console()
    if web_findings is not None:
        console.print(Panel(_web_summary_text(web_findings, web_meta), title="Summary"))
        if web_findings:
            console.print(web_findings_table(web_findings))
    else:
        console.print(
            Panel(
                f"[bold]blacklight-cli[/] v{__version__} - scan report\n"
                f"Targets: [bold]{meta.get('targets', '')}[/] | Hosts scanned: {meta.get('hosts_scanned', 0)} | "
                f"Services found: {meta.get('services_found', 0)} | Findings: {meta.get('findings_count', 0)}",
                title="Summary",
            )
        )
    hosts = host_risk_table(findings)
    if hosts:
        score_table = Table(title="Host risk scores", expand=True)
        score_table.add_column("Host")
        score_table.add_column("Risk score (0-100)")
        score_table.add_column("Findings")
        for row in hosts:
            score_table.add_row(row["host"], f"{row['score']:.1f}", str(row["findings"]))
        console.print(score_table)
    if findings:
        console.print(findings_table(findings))
    console.print(
        Panel(
            "Risk score: severity-weighted base (capped at 60) + 10 per KEV finding "
            "(capped at 20) + max EPSS x 10, capped at 100.\n"
            "For use only on systems you own or are authorized to test.",
            title="Notes",
        )
    )
```

Modify `export_report`:
```python
def export_report(
    findings: list[Finding],
    meta: dict,
    fmt: str,
    output: Path,
    web_findings: list[WebFinding] | None = None,
    web_meta: dict | None = None,
) -> Path:
    """Write the report in html, markdown, or json format."""
    payload = {
        "meta": meta,
        "findings": [f.to_dict() for f in findings],
        "hosts": host_risk_table(findings),
        "web": (
            {"meta": web_meta, "findings": [f.to_dict() for f in web_findings]}
            if web_findings is not None
            else None
        ),
    }
    if fmt == "json":
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif fmt == "html":
        output.write_text(
            _load_template("report.html.j2", autoescape=True).render(**payload),
            encoding="utf-8",
        )
    elif fmt == "markdown":
        output.write_text(
            _load_template("report.md.j2").render(**payload),
            encoding="utf-8",
        )
    else:
        raise ValueError(f"Unknown format: {fmt}")
    return output
```

Modify `blacklight/templates/report.html.j2` — insert between the findings table block and `<footer>`:
```html
{% if web %}
<h2>Web findings</h2>
<p>URL: <strong>{{ web.meta.url }}</strong> &middot; Checks run: {{ web.meta.checks_run }}
&middot; Checks errored: {{ web.meta.checks_errored }} &middot; Generated: {{ web.meta.generated }}</p>
<table>
<tr><th>Category</th><th>URL</th><th>Severity</th><th>Detail</th><th>Evidence</th></tr>
{% for f in web.findings %}
<tr class="{{ f.severity }}">
<td>{{ f.category }}</td><td>{{ f.url }}</td><td>{{ f.severity }}</td>
<td>{% if f.cve_id %}<a href="https://nvd.nist.gov/vuln/detail/{{ f.cve_id }}">{{ f.cve_id }}</a>: {% endif %}{{ f.detail }}</td>
<td>{{ f.evidence }}{% if f.epss is not none %} (EPSS {{ f.epss }}{% if f.in_kev %}, <span class="badge">KEV</span>{% endif %}){% endif %}</td>
</tr>
{% endfor %}
</table>
{% endif %}
```

Modify `blacklight/templates/report.md.j2` — append at the end:
```markdown
{% if web %}
## Web findings

URL: {{ web.meta.url }} | Checks run: {{ web.meta.checks_run }} | Checks errored: {{ web.meta.checks_errored }} | Generated: {{ web.meta.generated }}

| Category | URL | Severity | Detail | Evidence |
|----------|-----|----------|--------|----------|
{% for f in web.findings %}| {{ f.category }} | {{ f.url }} | {{ f.severity }} | {% if f.cve_id %}[{{ f.cve_id }}](https://nvd.nist.gov/vuln/detail/{{ f.cve_id }}): {% endif %}{{ f.detail }} | {{ f.evidence }}{% if f.epss is not none %} (EPSS {{ f.epss }}{% if f.in_kev %}, KEV{% endif %}){% endif %} |
{% endfor %}
{% endif %}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_reporter.py -q`
Expected: all pass. Then `python -m pytest -q` full suite green (68 + new, and existing reporter tests unchanged behavior).

- [ ] **Step 5: Commit**

```bash
git add blacklight/reporter.py blacklight/templates/report.html.j2 blacklight/templates/report.md.j2 tests/test_reporter.py
git commit -m "feat: render and export web findings in reports"
```

---

### Task 10: CLI `web` command

**Files:**
- Modify: `blacklight/cli.py`
- Test: `tests/test_cli_web.py`

**Interfaces:**
- Consumes: `guardrails.normalize_web_url`, `guardrails.verify_web_target`, `blacklight.web.engine.run_web_scan` (imported as `from blacklight.web.engine import run_web_scan` — tests monkeypatch `blacklight.cli.run_web_scan`), `reporter.render_terminal`, `reporter.export_report`, `paths.ensure_dirs`, `paths.SCAN_LOG`, existing `_log_scan` pattern.
- Produces: `cli.web` typer command, `cli._log_web_scan(url: str, permission: bool, meta: dict) -> None`. Follows the existing `scan` command's structure exactly (guardrail flow, format validation, suffix inference, graceful degradation, `Report written to [bold]{output}[/]`).

- [ ] **Step 1: Write the failing tests**

`tests/test_cli_web.py`:
```python
from typer.testing import CliRunner

from blacklight.cli import app
from blacklight.web.models import WebFinding

runner = CliRunner()


def _web_result():
    return {
        "findings": [WebFinding(url="http://127.0.0.1/", category="security_header",
                                detail="Missing CSP", severity="low", evidence="")],
        "meta": {"url": "http://127.0.0.1/", "host": "127.0.0.1", "resolved_ip": "127.0.0.1",
                 "checks_run": 19, "checks_errored": 0, "cve_findings": 0,
                 "generated": "2030-01-01T00:00:00+00:00"},
    }


def test_web_blocks_public_target_without_permission(monkeypatch):
    monkeypatch.setattr("blacklight.cli.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("8.8.8.8", 0))])
    result = runner.invoke(app, ["web", "https://example.com"])
    assert result.exit_code == 1
    assert "Blocked" in result.output


def test_web_prompts_for_public_target_with_permission(monkeypatch):
    monkeypatch.setattr("blacklight.cli.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("8.8.8.8", 0))])
    monkeypatch.setattr("blacklight.cli.typer.confirm", lambda *a, **k: False)
    result = runner.invoke(app, ["web", "https://example.com", "--i-have-permission"])
    assert result.exit_code == 1
    assert "Aborted" in result.output


def test_web_end_to_end_private_target(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.cli.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("127.0.0.1", 0))])
    monkeypatch.setattr("blacklight.cli.run_web_scan",
                        lambda *a, **k: type("R", (), _web_result())())
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    result = runner.invoke(app, ["web", "http://127.0.0.1"])
    assert result.exit_code == 0
    assert "web report" in result.output
    assert "Missing CSP" in result.output
    assert (tmp_path / "scan.log").exists()


def test_web_exports_json(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.cli.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("127.0.0.1", 0))])
    monkeypatch.setattr("blacklight.cli.run_web_scan",
                        lambda *a, **k: type("R", (), _web_result())())
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    out = tmp_path / "web.json"
    result = runner.invoke(app, ["web", "http://127.0.0.1", "-o", str(out)])
    assert result.exit_code == 0
    import json
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["web"]["findings"][0]["category"] == "security_header"
    assert "Report written to" in result.output


def test_web_fails_gracefully_on_upstream_error(monkeypatch, tmp_path):
    import requests
    monkeypatch.setattr("blacklight.cli.guardrails.socket.getaddrinfo",
                        lambda host, *a, **k: [("AF_INET", 1, 6, "", ("127.0.0.1", 0))])
    def boom(*a, **k):
        raise requests.ConnectionError("unable to reach target")

    monkeypatch.setattr("blacklight.cli.run_web_scan", boom)
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    result = runner.invoke(app, ["web", "http://127.0.0.1"])
    assert result.exit_code == 1
    assert "Web scan failed" in result.output
    assert "Traceback" not in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_web.py -q`
Expected: FAIL — typer error: no such command `web` / `Unsupported operation`.

- [ ] **Step 3: Write the implementation**

Modify `blacklight/cli.py`:

Add import:
```python
from blacklight.web.engine import run_web_scan
```

Add after the `scan` command (before `version`), plus the `_log_web_scan` helper after `_log_scan`:
```python
@app.command()
def web(
    url: str = typer.Argument(..., help="Web target URL (hostname or http(s) URL)."),
    i_have_permission: bool = typer.Option(
        False, "--i-have-permission",
        help="Confirm you are authorized to scan this target.",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the local NVD/EPSS cache."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Export report to a file."),
    fmt: str = typer.Option("html", "--format", help="Export format: html, markdown, json."),
    timeout: int = typer.Option(30, "--timeout", help="HTTP request timeout in seconds."),
) -> None:
    """Scan a web application for misconfigurations and injection flaws."""
    paths.ensure_dirs()
    url = guardrails.normalize_web_url(url)
    verdict = guardrails.verify_web_target(url, i_have_permission)
    for blocked in verdict.blocked:
        console.print(f"[red]Blocked:[/] {blocked} must be an http(s) URL for a private "
                      "host, or pass --i-have-permission for public hosts.")
    if verdict.needs_confirmation:
        if not typer.confirm(f"Target {url} is public. Are you authorized to scan it?"):
            console.print("[yellow]Aborted.[/]")
            raise typer.Exit(code=1)
    if not (verdict.allowed or verdict.needs_confirmation):
        console.print("[red]No scannable targets.[/]")
        raise typer.Exit(code=1)
    if fmt not in ("html", "markdown", "json"):
        console.print("[red]Invalid format.[/] Choose html, markdown, or json.")
        raise typer.Exit(code=1)
    if output is not None and fmt == "html" and output.suffix in (".md", ".json"):
        fmt = "markdown" if output.suffix == ".md" else "json"

    try:
        result = run_web_scan(url, timeout, no_cache)
    except (
        requests.RequestException,
        subprocess.TimeoutExpired,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        console.print(f"[red]Web scan failed:[/] {exc}")
        raise typer.Exit(code=1)
    _log_web_scan(url, i_have_permission, result.meta)
    render_terminal([], {}, web_findings=result.findings, web_meta=result.meta)
    if output is not None:
        export_report([], {}, fmt, output,
                      web_findings=result.findings, web_meta=result.meta)
        console.print(f"Report written to [bold]{output}[/]")
```

Add after `_log_scan`:
```python
def _log_web_scan(url: str, permission: bool, meta: dict) -> None:
    """Append one line per web scan to ~/.blacklight/scan.log."""
    line = (
        f"{meta['generated']} url={meta['url']} "
        f"permission={permission} checks={meta['checks_run']} "
        f"errors={meta['checks_errored']} findings={meta['cve_findings']}\n"
    )
    with paths.SCAN_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_web.py -q`
Expected: 5 passed. Then `python -m pytest -q` full suite green.

- [ ] **Step 5: Commit**

```bash
git add blacklight/cli.py tests/test_cli_web.py
git commit -m "feat: add web scan command with guardrails and export"
```

---

### Task 11: README web scanning section

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the final CLI surface from Task 10.

- [ ] **Step 1: Write the failing check (manual verification)**

The README has no automated test; verification is a `grep` for the new sections. Run:
```bash
git grep -c "blacklight web" README.md
```
Expected: exit code 1 (no match yet).

- [ ] **Step 2: Implement**

Add a `## Web scanning` section to `README.md` between the existing `## Guardrails` and `## Development` sections:

```markdown
## Web scanning

Probes a web application for common misconfigurations and injection flaws
(passive, error-based detection — no exploitation, no blind/timing techniques).

```bash
# Scan a local web app (private targets need no flag)
blacklight web http://127.0.0.1:8080

# Scan a public site you are authorized to test (interactive confirmation)
blacklight web https://example.com --i-have-permission

# Export
blacklight web http://127.0.0.1:8080 -o web_report.html
```

Checks: missing security headers (X-Frame-Options, CSP, HSTS, ...), exposed
files and admin paths (`.git/config`, `.env`, `phpinfo`, `wp-admin`, backups),
directory listing, default install pages, error-based SQLi / reflected XSS /
command-injection probes on discovered GET parameters, and tech fingerprinting
(server/framework versions) fed through the same CPE → NVD CVE pipeline as
network scans. Web findings are scored by severity and exported alongside
network findings in HTML/Markdown/JSON reports.
```

- [ ] **Step 3: Verify**

Run: `git grep -c "blacklight web" README.md` — now matches (3). Run `python -m pytest -q` — full suite green.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document web scanning in README"
```

---

## Self-Review Notes

Plan bugs fixed during self-review (the plan bodies contain only the corrected code; flagged here for reviewers):
1. Task 8 first draft used `Finding.detail_text()` — no such method; the conversion uses `f.description`.
2. Task 10 first draft subscripted the `WebResult` dataclass (`result["findings"]`); the CLI uses attribute access `result.findings`/`result.meta`, and the test helper returns an object with attributes (`type("R", (), {...})()`), so tests and implementation agree.
3. Task 8 `test_run_web_scan_counts_errored_checks`: header checks never call the probe, so a failing probe could not produce `checks_errored > 0` while suppressing header findings; the test page now ships all headers present so only probe-dependent checks error out.
4. Task 9's `render_terminal` change uses `meta.get(...)` so a web-only run with `meta={}` cannot KeyError; existing network behavior is unchanged when `web_findings is None`.
5. Task 7/9 test imports (`web_risk_score`, `web_findings_table`) and the web risk score arithmetic (1+10=11.0, not 14.0) corrected in the test code.
