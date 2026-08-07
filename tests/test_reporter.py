import json

import pytest
from rich.console import Console

from blacklight.cve_matcher import Finding
from blacklight.reporter import (export_report, findings_table, host_risk_table,
                                 render_terminal, tls_findings_table)

META = {"targets": "192.168.1.10", "hosts_scanned": 1, "services_found": 2,
        "findings_count": 2, "generated": "2030-01-01T00:00:00+00:00"}


def _finding(host="192.168.1.10", cve_id="CVE-2024-12345", severity="critical",
             cvss=9.8, epss=0.9, in_kev=True) -> Finding:
    return Finding(
        host=host, port=22, service="OpenSSH", version="9.6p1",
        cpe="cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", cve_id=cve_id,
        description="Sample <vuln> & description", cvss_score=cvss, severity=severity,
        fixed_version="9.7", epss=epss, in_kev=in_kev,
    )


def _result(findings=None, web=False):
    from blacklight.engine import NetworkMeta, ScanResult, WebMeta

    findings = findings or []
    if not web:
        return ScanResult(kind="scan", target="192.168.1.10",
                          generated="2030-01-01T00:00:00+00:00",
                          findings=findings, web_findings=[],
                          meta=NetworkMeta(targets="192.168.1.10",
                                           hosts_scanned=1,
                                           services_found=2,
                                           findings_count=len(findings),
                                           generated="2030-01-01T00:00:00+00:00"))
    return ScanResult(kind="web", target="http://example.com/",
                      generated="2030-01-01T00:00:00+00:00", findings=[],
                      web_findings=findings,
                      meta=WebMeta(url="http://example.com/", host="example.com",
                                   resolved_ip="127.0.0.1", checks_run=18,
                                   checks_errored=0, cve_findings=0,
                                   generated="2030-01-01T00:00:00+00:00"))


def test_render_terminal_prints_summary():
    console = Console(record=True, width=160)
    render_terminal(_result([_finding()]), console=console)
    text = console.export_text()
    assert "Summary" in text
    assert "CVE-2024-12345" in text
    assert "critica" in text


def test_findings_table_sorted_by_cvss_desc():
    low = _finding(cve_id="CVE-2023-0001", severity="low", cvss=2.0)
    high = _finding(cve_id="CVE-2023-0002", severity="critical", cvss=10.0)
    table = findings_table([low, high])
    first = [list(column.cells)[0] for column in table.columns]
    assert "CVE-2023-0002" in first


def test_host_risk_table_sorted_by_score_desc():
    rows = host_risk_table([_finding(host="10.0.0.2"), _finding(host="10.0.0.1")])
    assert rows[0]["host"] == "10.0.0.2"
    assert rows[1]["host"] == "10.0.0.1"


def test_export_json(tmp_path):
    out = export_report(_result([_finding()]), "json", tmp_path / "report.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["targets"] == "192.168.1.10"
    assert data["findings"][0]["cve_id"] == "CVE-2024-12345"
    assert data["hosts"][0]["score"] > 0


def test_export_html_escapes_and_renders(tmp_path):
    out = export_report(_result([_finding()]), "html", tmp_path / "report.html")
    html = out.read_text(encoding="utf-8")
    assert "&lt;vuln&gt;" in html
    assert "CVE-2024-12345" in html
    assert "Host risk scores" in html


def test_export_markdown(tmp_path):
    out = export_report(_result([_finding()]), "markdown", tmp_path / "report.md")
    md = out.read_text(encoding="utf-8")
    assert "| CVE |" in md
    assert "CVE-2024-12345" in md


def test_export_unknown_format_raises(tmp_path):
    with pytest.raises(ValueError):
        export_report(_result([]), "pdf", tmp_path / "report.pdf")


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
    render_terminal(_result(_web_findings(), web=True), Console(file=out, width=160))
    text = out.getvalue()
    assert "web report" in text
    assert "Checks run: 18" in text
    assert "Web risk score: 11.0" in text
    assert "Possible SQL injection" in text


def test_render_terminal_without_web_section_unaffected():
    import io
    from rich.console import Console
    out = io.StringIO()
    render_terminal(_result([]), Console(file=out))
    text = out.getvalue()
    assert "Web risk score" not in text


def test_render_terminal_has_footer():
    console = Console(record=True, width=160)
    render_terminal(_result([_finding()]), console=console)
    assert "Scan complete" in console.export_text()


def test_render_terminal_risk_gauge_in_score_table():
    console = Console(record=True, width=160)
    render_terminal(_result([_finding()]), console=console)
    text = console.export_text()
    assert "░" in text
    assert "█" in text


from blacklight.tls import TlsFinding


def _tls_finding(severity="high", cve_id="TLS-EXPIRED", detail="expired") -> TlsFinding:
    return TlsFinding(host="192.168.1.10", port=443, service="https",
                      category="expiry", detail=detail, evidence="notAfter 2029-01-01",
                      severity=severity, cve_id=cve_id)


def _tls_result():
    from blacklight.engine import NetworkMeta, ScanResult

    return ScanResult(
        kind="scan", target="192.168.1.10", generated="2030-01-01T00:00:00+00:00",
        findings=[], web_findings=[],
        tls_findings=[_tls_finding()],
        meta=NetworkMeta(targets="192.168.1.10", hosts_scanned=1, services_found=1,
                         findings_count=0, tls_findings_count=1,
                         generated="2030-01-01T00:00:00+00:00"))


def test_tls_findings_table_columns():
    table = tls_findings_table([_tls_finding()])
    assert table.title == "TLS findings"
    assert [c.header for c in table.columns] == ["Host", "Port", "Service",
                                                 "Category", "Severity", "Detail", "Evidence"]


def test_render_terminal_includes_tls_section():
    import io
    from rich.console import Console

    out = io.StringIO()
    render_terminal(_tls_result(), Console(file=out, width=160))
    text = out.getvalue()
    assert "TLS findings" in text
    assert "TLS-EXPIRED" in text


def test_export_json_includes_tls(tmp_path):
    out = export_report(_tls_result(), "json", tmp_path / "tls.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tls"][0]["cve_id"] == "TLS-EXPIRED"


def test_export_html_includes_tls_section(tmp_path):
    out = export_report(_tls_result(), "html", tmp_path / "tls.html")
    html = out.read_text(encoding="utf-8")
    assert "TLS findings" in html
    assert "TLS-EXPIRED" in html


def test_export_markdown_includes_tls_section(tmp_path):
    out = export_report(_tls_result(), "markdown", tmp_path / "tls.md")
    md = out.read_text(encoding="utf-8")
    assert "## TLS findings" in md
    assert "TLS-EXPIRED" in md


def test_export_html_without_tls_omits_section(tmp_path):
    out = export_report(_result([_finding()]), "html", tmp_path / "plain.html")
    assert "TLS findings" not in out.read_text(encoding="utf-8")


def test_host_risk_table_folds_tls_findings():
    rows = host_risk_table(
        [_finding(host="10.0.0.1", severity="low", in_kev=False, epss=0.0)],
        tls_findings=[_tls_finding()],
    )
    by_host = {row["host"]: row for row in rows}
    assert by_host["192.168.1.10"]["score"] == 10.0
    assert by_host["192.168.1.10"]["findings"] == 1
    assert by_host["10.0.0.1"]["score"] == 1.0


def test_render_terminal_host_risk_includes_tls():
    console = Console(record=True, width=160)
    render_terminal(_tls_result(), console=console)
    text = console.export_text()
    assert "Host risk scores" in text
    assert "10.0" in text
