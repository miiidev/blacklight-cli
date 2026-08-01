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
