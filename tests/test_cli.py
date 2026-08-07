import requests
from types import SimpleNamespace
from typer.testing import CliRunner

from blacklight import __version__
from blacklight.cli import app, engine, execute_scan, execute_web
from blacklight.cve_matcher import Finding
from blacklight.scanner import ScanRecord

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert f"blacklight-cli {__version__}" in result.output


def test_banner_printed_on_invocation():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "██████╗" in result.output


def test_scan_blocks_public_target_without_permission(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("nmap should not run for blocked targets")

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", fail)
    result = runner.invoke(app, ["scan", "8.8.8.8"])
    assert result.exit_code == 1
    assert "Blocked" in result.output


def test_scan_prompts_for_public_target_with_permission(monkeypatch):
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", lambda *a, **k: [])
    monkeypatch.setattr("blacklight.cli.typer.confirm", lambda *a, **k: False)
    result = runner.invoke(app, ["scan", "8.8.8.8", "--i-have-permission"])
    assert result.exit_code == 1
    assert "Aborted" in result.output


def test_scan_end_to_end_private_target(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.os.environ", {})
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.engine.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings", lambda findings, **k: findings)
    result = runner.invoke(app, ["scan", "192.168.1.10", "--ports", "22"])
    assert result.exit_code == 0
    assert "scan report" in result.output
    assert "Hosts scanned: 1" in result.output
    assert (tmp_path / "scan.log").exists()


def test_scan_exports_json_output(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", lambda *a, **k: [])
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.os.environ", {})
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    out = tmp_path / "report.json"

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.engine.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings", lambda findings, **k: findings)
    result = runner.invoke(app, ["scan", "192.168.1.10", "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "Report written to" in result.output


def test_scan_reports_missing_nmap(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: None)
    monkeypatch.setattr("blacklight.engine.os.environ", {})
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    result = runner.invoke(app, ["scan", "192.168.1.10"])
    assert result.exit_code == 1
    assert "nmap not found" in result.output
    assert "apt install nmap" in result.output


def test_scan_fails_gracefully_on_upstream_error(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise requests.ConnectionError("unable to reach nvd.nist.gov")

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", boom)
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.os.environ", {})
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
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

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", fail)
    code = execute_scan(["8.8.8.8"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=False, confirm=never_confirm)
    assert code == 1
    assert "Blocked" in capsys.readouterr().out


def test_execute_scan_aborts_when_confirm_declines(monkeypatch, tmp_path, capsys):
    def fail(*a, **k):
        raise AssertionError("scan pipeline must not run when confirm declines")

    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", fail)
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
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
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.os.environ", {})
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.engine.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings",
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
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.os.environ", {})
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.engine.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    code = execute_scan(["192.168.1.10"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=False, confirm=never_confirm)
    assert code == 0


def test_execute_scan_exports_report(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.os.environ", {})
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.engine.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings",
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


def _web_scan_result():
    from blacklight.engine import ScanResult, WebMeta

    return ScanResult(
        kind="web", target="http://127.0.0.1",
        generated=WEB_META["generated"], findings=[], web_findings=[],
        meta=WebMeta(url=WEB_META["url"], host="127.0.0.1",
                     resolved_ip=WEB_META["resolved_ip"],
                     checks_run=WEB_META["checks_run"],
                     checks_errored=WEB_META["checks_errored"],
                     cve_findings=WEB_META["cve_findings"],
                     generated=WEB_META["generated"]),
    )


def test_execute_web_blocks_public_without_permission(monkeypatch, capsys):
    def fail(*a, **k):
        raise AssertionError("web pipeline must not run for blocked targets")

    monkeypatch.setattr("blacklight.engine.guardrails.resolve_hostname",
                        lambda h: "1.2.3.4")
    monkeypatch.setattr("blacklight.engine.WebScan.run", fail)
    code = execute_web("https://example.com", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=False, confirm=never_confirm)
    assert code == 1
    assert "Blocked" in capsys.readouterr().out


def test_execute_web_aborts_when_confirm_declines(monkeypatch, tmp_path, capsys):
    def fail(*a, **k):
        raise AssertionError("web pipeline must not run when confirm declines")

    monkeypatch.setattr("blacklight.engine.guardrails.resolve_hostname",
                        lambda h: "1.2.3.4")
    monkeypatch.setattr("blacklight.engine.WebScan.run", fail)
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
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
    monkeypatch.setattr("blacklight.engine.guardrails.resolve_hostname",
                        lambda h: "1.2.3.4")
    monkeypatch.setattr("blacklight.engine.WebScan.run",
                        lambda self, targets, params, on_progress=None:
                        _web_scan_result())
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    calls = []
    code = execute_web("https://example.com", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=True,
                       confirm=lambda m: calls.append(m) or True)
    assert code == 0
    assert calls
    assert "Web risk score" in capsys.readouterr().out


def test_execute_web_private_target_skips_confirm(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.engine.WebScan.run",
                        lambda self, targets, params, on_progress=None:
                        _web_scan_result())
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    code = execute_web("http://127.0.0.1", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=False, confirm=never_confirm)
    assert code == 0


def test_execute_web_exports_report(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("blacklight.engine.WebScan.run",
                        lambda self, targets, params, on_progress=None:
                        _web_scan_result())
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    out = tmp_path / "web.json"
    code = execute_web("http://127.0.0.1", timeout=30, no_cache=False,
                       output=out, fmt="json",
                       permission_granted=False, confirm=never_confirm)
    assert code == 0
    assert out.exists()
    assert "Report written to" in capsys.readouterr().out


def test_execute_scan_records_history(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.engine.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.engine.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.engine.os.environ", {})
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.engine.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.engine.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    from blacklight import history
    assert history.list_recent() == []
    code = execute_scan(["192.168.1.10"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=False, confirm=never_confirm)
    assert code == 0
    rows = history.list_recent()
    assert len(rows) == 1
    assert rows[0].kind == "scan"
    assert rows[0].target == "192.168.1.10"
    assert rows[0].hosts == 1
    assert rows[0].findings_count == 0


def test_execute_web_records_history(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.engine.WebScan.run",
                        lambda self, targets, params, on_progress=None:
                        _web_scan_result())
    monkeypatch.setattr("blacklight.engine.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.engine.paths.SCAN_LOG", tmp_path / "scan.log")
    from blacklight import history
    code = execute_web("http://127.0.0.1", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=False, confirm=never_confirm)
    assert code == 0
    rows = history.list_recent()
    assert len(rows) == 1
    assert rows[0].kind == "web"
    assert rows[0].target == "http://127.0.0.1"


def test_history_list_after_scan(monkeypatch, tmp_path):
    from blacklight import engine, history
    result = engine.ScanResult(
        kind="scan", target="192.168.1.10", generated="2026-08-04T10:00:00+00:00",
        findings=[], web_findings=[],
        meta=engine.NetworkMeta(targets="192.168.1.10", hosts_scanned=1,
                                services_found=1, findings_count=0,
                                generated="2026-08-04T10:00:00+00:00"),
    )
    history.record_scan(result, False)
    result2 = runner.invoke(app, ["history"], env={"COLUMNS": "200"})
    assert result2.exit_code == 0
    assert "192.168.1.10" in result2.output


def test_history_list_empty_exits_zero():
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "No scan history yet" in result.output


def test_history_diff_no_previous_scan_exits_zero():
    from blacklight import engine, history
    result = engine.ScanResult(
        kind="scan", target="192.168.1.10", generated="2026-08-04T10:00:00+00:00",
        findings=[], web_findings=[],
        meta=engine.NetworkMeta(targets="192.168.1.10", hosts_scanned=1,
                                services_found=1, findings_count=0,
                                generated="2026-08-04T10:00:00+00:00"),
    )
    history.record_scan(result, False)
    out = runner.invoke(app, ["history", "diff", "192.168.1.10"])
    assert out.exit_code == 0
    assert "No previous scan of 192.168.1.10" in out.output


def test_history_diff_unknown_target_exits_zero():
    result = runner.invoke(app, ["history", "diff", "10.0.0.99"])
    assert result.exit_code == 0
    assert "No scans of 10.0.0.99 yet." in result.output


def test_history_diff_bad_since_exits_one():
    result = runner.invoke(app, ["history", "diff", "10.0.0.99", "--since", "nope"])
    assert result.exit_code == 1
    assert "invalid --since value: nope" in result.output


def test_history_trend_unknown_target_exits_zero():
    result = runner.invoke(app, ["history", "trend", "10.0.0.99"])
    assert result.exit_code == 0
    assert "No scans of 10.0.0.99 yet." in result.output


def test_history_trend_bad_limit_exits_one():
    result = runner.invoke(app, ["history", "trend", "10.0.0.99", "--limit", "0"])
    assert result.exit_code == 1
    assert "LIMIT must be a positive integer" in result.output


def test_history_corrupt_db_exits_one(monkeypatch, tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not a sqlite database")
    monkeypatch.setattr("blacklight.paths.HISTORY_DB", bad)
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 1
    assert "History database error" in result.output


def test_history_help_lists_subcommands():
    result = runner.invoke(app, ["history", "--help"])
    assert result.exit_code == 0
    assert "diff" in result.output
    assert "trend" in result.output
