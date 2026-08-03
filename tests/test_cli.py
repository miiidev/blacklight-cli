import requests
from types import SimpleNamespace
from typer.testing import CliRunner

from blacklight import __version__
from blacklight.cli import app, execute_scan, execute_web, run_scan
from blacklight.cve_matcher import Finding
from blacklight.scanner import ScanRecord

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "blacklight-cli 0.1.0" in result.output


def test_banner_printed_on_invocation():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "██████╗" in result.output


def test_scan_blocks_public_target_without_permission(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("nmap should not run for blocked targets")

    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", fail)
    result = runner.invoke(app, ["scan", "8.8.8.8"])
    assert result.exit_code == 1
    assert "Blocked" in result.output


def test_scan_prompts_for_public_target_with_permission(monkeypatch):
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: [])
    monkeypatch.setattr("blacklight.cli.typer.confirm", lambda *a, **k: False)
    result = runner.invoke(app, ["scan", "8.8.8.8", "--i-have-permission"])
    assert result.exit_code == 1
    assert "Aborted" in result.output


def test_scan_end_to_end_private_target(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings", lambda findings, **k: findings)
    result = runner.invoke(app, ["scan", "192.168.1.10", "--ports", "22"])
    assert result.exit_code == 0
    assert "scan report" in result.output
    assert "Hosts scanned: 1" in result.output
    assert (tmp_path / "scan.log").exists()


def test_scan_exports_json_output(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: [])
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    out = tmp_path / "report.json"

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings", lambda findings, **k: findings)
    result = runner.invoke(app, ["scan", "192.168.1.10", "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "Report written to" in result.output


def test_run_scan_builds_meta(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    result = run_scan(["192.168.1.10"], "22", 30, False)
    assert result["meta"]["hosts_scanned"] == 1
    assert result["meta"]["services_found"] == 1
    assert result["meta"]["findings_count"] == 0
    assert result["findings"] == []


def test_scan_reports_missing_nmap(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: None)
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    result = runner.invoke(app, ["scan", "192.168.1.10"])
    assert result.exit_code == 1
    assert "nmap not found" in result.output
    assert "apt install nmap" in result.output


def test_scan_fails_gracefully_on_upstream_error(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise requests.ConnectionError("unable to reach nvd.nist.gov")

    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", boom)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    result = runner.invoke(app, ["scan", "192.168.1.10"])
    assert result.exit_code == 1
    assert "Scan failed" in result.output
    assert "Traceback" not in result.output
    assert not (tmp_path / "scan.log").exists()

def never_confirm(message):
    raise AssertionError("confirm must not be called")


def test_execute_scan_blocks_public_target_without_permission(monkeypatch, capsys):
    def fail(*a, **k):
        raise AssertionError("scan pipeline must not run for blocked targets")

    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", fail)
    code = execute_scan(["8.8.8.8"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=False, confirm=never_confirm)
    assert code == 1
    assert "Blocked" in capsys.readouterr().out


def test_execute_scan_aborts_when_confirm_declines(monkeypatch, tmp_path, capsys):
    def fail(*a, **k):
        raise AssertionError("scan pipeline must not run when confirm declines")

    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", fail)
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    calls = []

    def declining(message):
        calls.append(message)
        return False

    code = execute_scan(["8.8.8.8"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=True, confirm=declining)
    assert code == 1
    assert calls
    assert "Aborted" in capsys.readouterr().out
    assert not (tmp_path / "scan.log").exists()


def test_execute_scan_confirm_true_proceeds(monkeypatch, tmp_path, capsys):
    records = [ScanRecord(host="8.8.8.8", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    calls = []
    code = execute_scan(["8.8.8.8"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=True,
                        confirm=lambda m: calls.append(m) or True)
    assert code == 0
    assert calls
    out = capsys.readouterr().out
    assert "scan report" in out
    assert "Hosts scanned: 1" in out


def test_execute_scan_private_target_skips_confirm(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    code = execute_scan(["192.168.1.10"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=False, confirm=never_confirm)
    assert code == 0


def test_execute_scan_exports_report(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    out = tmp_path / "report.json"
    code = execute_scan(["192.168.1.10"], ports="22", timeout=30, no_cache=False,
                        output=out, fmt="json",
                        permission_granted=False, confirm=never_confirm)
    assert code == 0
    assert out.exists()

WEB_META = {
    "url": "https://example.com",
    "resolved_ip": "1.2.3.4",
    "checks_run": 1,
    "checks_errored": 0,
    "cve_findings": 0,
    "generated": "2026-08-04T00:00:00+00:00",
}


def test_execute_web_blocks_public_without_permission(monkeypatch, capsys):
    def fail(*a, **k):
        raise AssertionError("web pipeline must not run for blocked targets")

    monkeypatch.setattr("blacklight.cli.guardrails.resolve_hostname",
                        lambda h: "1.2.3.4")
    monkeypatch.setattr("blacklight.cli.run_web_scan", fail)
    code = execute_web("https://example.com", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=False, confirm=never_confirm)
    assert code == 1
    assert "Blocked" in capsys.readouterr().out


def test_execute_web_aborts_when_confirm_declines(monkeypatch, tmp_path, capsys):
    def fail(*a, **k):
        raise AssertionError("web pipeline must not run when confirm declines")

    monkeypatch.setattr("blacklight.cli.guardrails.resolve_hostname",
                        lambda h: "1.2.3.4")
    monkeypatch.setattr("blacklight.cli.run_web_scan", fail)
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    calls = []

    def declining(message):
        calls.append(message)
        return False

    code = execute_web("https://example.com", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=True, confirm=declining)
    assert code == 1
    assert calls
    assert "Aborted" in capsys.readouterr().out
    assert not (tmp_path / "scan.log").exists()


def test_execute_web_confirm_true_proceeds(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("blacklight.cli.guardrails.resolve_hostname",
                        lambda h: "1.2.3.4")
    monkeypatch.setattr("blacklight.cli.run_web_scan",
                        lambda *a, **k: SimpleNamespace(findings=[], meta=WEB_META))
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    calls = []
    code = execute_web("https://example.com", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=True,
                       confirm=lambda m: calls.append(m) or True)
    assert code == 0
    assert calls
    assert "Web risk score" in capsys.readouterr().out


def test_execute_web_private_target_skips_confirm(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.cli.run_web_scan",
                        lambda *a, **k: SimpleNamespace(findings=[], meta=WEB_META))
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    code = execute_web("http://127.0.0.1", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=False, confirm=never_confirm)
    assert code == 0


def test_execute_web_exports_report(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("blacklight.cli.run_web_scan",
                        lambda *a, **k: SimpleNamespace(findings=[], meta=WEB_META))
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    out = tmp_path / "web.json"
    code = execute_web("http://127.0.0.1", timeout=30, no_cache=False,
                       output=out, fmt="json",
                       permission_granted=False, confirm=never_confirm)
    assert code == 0
    assert out.exists()
    assert "Report written to" in capsys.readouterr().out
