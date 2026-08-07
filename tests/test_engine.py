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


def _params(**extra):
    from blacklight.engine import ScanParams

    defaults = dict(permission_granted=False, timeout=30, no_cache=False,
                    ports=None, output=None, fmt="html")
    defaults.update(extra)
    return ScanParams(**defaults)


def never_confirm(message):
    raise AssertionError("confirm must not be called")


def _monkey_engine(monkeypatch, tmp_path, records=None, client=None):
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts",
                        lambda *a, **k: records or [])
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.os", SimpleNamespace(environ={}))
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    monkeypatch.setattr("blacklight.engine.paths.HISTORY_DB", tmp_path / "history.db")
    monkeypatch.setattr("blacklight.engine.NvdClient", client or _FakeClient)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings",
                        lambda findings, **k: findings)


def test_run_blocks_public_target_without_permission(monkeypatch, tmp_path, capsys):
    from blacklight.engine import NetworkScan, run

    def boom(*a, **k):
        raise AssertionError("nmap must not run for blocked targets")

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", boom)
    code = run(NetworkScan(), ["8.8.8.8"],
               _params(permission_granted=False), confirm=never_confirm)
    assert code == 1
    assert "Blocked" in capsys.readouterr().out


def test_run_aborts_when_confirm_declines(monkeypatch, capsys):
    from blacklight.engine import NetworkScan, run

    def boom(*a, **k):
        raise AssertionError("nmap must not run after declining")

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", boom)
    calls = []

    def declining(message):
        calls.append(message)
        return False

    code = run(NetworkScan(), ["8.8.8.8"],
               _params(permission_granted=True), confirm=declining)
    assert code == 1
    assert calls
    assert "Aborted" in capsys.readouterr().out


def test_run_private_target_skips_confirm_and_records_history(monkeypatch, tmp_path):
    from blacklight import history
    from blacklight.engine import NetworkScan, run

    _monkey_engine(monkeypatch, tmp_path, records=_network_records())
    code = run(NetworkScan(), ["192.168.1.10"],
               _params(ports="22"), confirm=never_confirm)
    assert code == 0
    rows = history.list_recent()
    assert len(rows) == 1
    assert rows[0].kind == "scan"
    assert rows[0].target == "192.168.1.10"
    assert rows[0].hosts == 1


def test_run_exports_json(monkeypatch, tmp_path, capsys):
    from blacklight.engine import NetworkScan, run

    _monkey_engine(monkeypatch, tmp_path, records=_network_records())
    out = tmp_path / "report.json"
    code = run(NetworkScan(), ["192.168.1.10"],
               _params(output=out, fmt="json"), confirm=never_confirm)
    assert code == 0
    assert out.exists()
    assert "Report written to" in capsys.readouterr().out


def test_run_returns_1_on_upstream_error(monkeypatch, tmp_path, capsys):
    import requests

    from blacklight.engine import NetworkScan, run

    def boom(*a, **k):
        raise requests.ConnectionError("unable to reach nvd.nist.gov")

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", boom)
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    monkeypatch.setattr("blacklight.engine.paths.HISTORY_DB", tmp_path / "history.db")
    code = run(NetworkScan(), ["192.168.1.10"], _params(), confirm=never_confirm)
    assert code == 1
    assert "Scan failed" in capsys.readouterr().out
    assert not (tmp_path / "scan.log").exists()


def test_run_reports_missing_nmap(monkeypatch, capsys):
    from blacklight.engine import NetworkScan, run

    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: None)
    code = run(NetworkScan(), ["192.168.1.10"], _params(), confirm=never_confirm)
    assert code == 1
    assert "nmap not found" in capsys.readouterr().out