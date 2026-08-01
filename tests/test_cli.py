from typer.testing import CliRunner

from blacklight.cli import app, run_scan
from blacklight.cve_matcher import Finding
from blacklight.scanner import ScanRecord

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "blacklight-cli 0.1.0" in result.output


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
