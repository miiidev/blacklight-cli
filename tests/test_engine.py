"""Scan pipeline seam tests: adapters, typed results, orchestrator."""

from types import SimpleNamespace

import pytest

from blacklight.engine import NetworkScan, ScanResult, WebScan, port_for_url
from blacklight.web.http import Page
from blacklight.web.models import WebFinding


class _FakeClient:
    def __init__(self, *a, **k):
        pass

    def lookup(self, cpe):
        return []


def _page(url="https://example.com/", status=200, headers=None, text="hello"):
    return Page(url=url, status=status, headers=headers or {}, text=text)


def _network_records():
    from blacklight.scanner import ScanRecord

    return [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                       service="OpenSSH", version="9.6p1")]


def test_port_for_url():
    assert port_for_url("http://example.com") == 80
    assert port_for_url("https://example.com") == 443
    assert port_for_url("https://example.com:8443") == 8443


def test_network_scan_runs_pipeline_and_meta(monkeypatch):
    from blacklight.engine import NetworkMeta

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts",
                        lambda *a, **k: _network_records())
    monkeypatch.setattr("blacklight.engine.NvdClient", _FakeClient)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    result = NetworkScan().run(["192.168.1.10"],
                               SimpleNamespace(ports="22", timeout=30, no_cache=False))
    assert isinstance(result, ScanResult)
    assert result.kind == "scan"
    assert isinstance(result.meta, NetworkMeta)
    assert result.meta.hosts_scanned == 1
    assert result.meta.services_found == 1
    assert result.meta.findings_count == 0
    assert result.findings == []
    assert result.generated.endswith("+00:00")


def test_web_scan_runs_checks_and_meta(monkeypatch):
    from blacklight.engine import WebMeta

    page = _page(text='<a href="/search?q=x">S</a>',
                 headers={"X-Frame-Options": "DENY"})
    monkeypatch.setattr("blacklight.engine.http.fetch_page", lambda *a, **k: page)
    monkeypatch.setattr("blacklight.engine.http.probe",
                        lambda target_url, params=None, timeout=30, **k:
                        type("P", (), {"status": 200, "text": "ok"})())
    monkeypatch.setattr("blacklight.engine.guardrails.resolve_hostname",
                        lambda host: "192.168.1.10")
    monkeypatch.setattr("blacklight.engine.NvdClient", _FakeClient)
    result = WebScan().run(["https://example.com/"],
                           SimpleNamespace(timeout=30, no_cache=False))
    assert result.kind == "web"
    assert result.target == "https://example.com/"
    assert isinstance(result.meta, WebMeta)
    assert result.meta.checks_run > 0
    assert result.meta.host == "example.com"
    assert result.web_findings


def test_web_scan_cve_findings_from_fingerprint(monkeypatch):
    from blacklight.cve_matcher import CVE

    page = _page(headers={"Server": "Apache/2.4.49"})
    monkeypatch.setattr("blacklight.engine.http.fetch_page", lambda *a, **k: page)
    monkeypatch.setattr("blacklight.engine.http.probe",
                        lambda *a, **k: type("P", (), {"status": 404, "text": "no"})())
    monkeypatch.setattr("blacklight.engine.guardrails.resolve_hostname",
                        lambda host: "192.168.1.10")

    class FindCve:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            assert cpe.startswith("cpe:2.3:a:apache:http_server:2.4.49")
            return [CVE("CVE-2021-41773", "Path traversal", 9.8, "critical", "2.4.50")]

    monkeypatch.setattr("blacklight.engine.NvdClient", FindCve)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    result = WebScan().run(["https://example.com/"],
                           SimpleNamespace(timeout=30, no_cache=False))
    cve_findings = [f for f in result.web_findings if f.category == "fingerprint"]
    assert len(cve_findings) == 1
    assert cve_findings[0].cve_id == "CVE-2021-41773"
    assert result.meta.cve_findings == 1