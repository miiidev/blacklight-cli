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
                        lambda url, params=None, timeout=30, **k: type("P", (), {"status": 200, "text": "ok"})())
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
                        lambda url, params=None, timeout=30, **k: type("P", (), {"status": 200, "text": "ok"})())
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
