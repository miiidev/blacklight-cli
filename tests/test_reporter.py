import json

import pytest
from rich.console import Console

from blacklight.cve_matcher import Finding
from blacklight.reporter import export_report, findings_table, host_risk_table, render_terminal

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


def test_render_terminal_prints_summary():
    console = Console(record=True, width=160)
    render_terminal([_finding()], META, console=console)
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
    out = export_report([_finding()], META, "json", tmp_path / "report.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["targets"] == "192.168.1.10"
    assert data["findings"][0]["cve_id"] == "CVE-2024-12345"
    assert data["hosts"][0]["score"] > 0


def test_export_html_escapes_and_renders(tmp_path):
    out = export_report([_finding()], META, "html", tmp_path / "report.html")
    html = out.read_text(encoding="utf-8")
    assert "&lt;vuln&gt;" in html
    assert "CVE-2024-12345" in html
    assert "Host risk scores" in html


def test_export_markdown(tmp_path):
    out = export_report([_finding()], META, "markdown", tmp_path / "report.md")
    md = out.read_text(encoding="utf-8")
    assert "| CVE |" in md
    assert "CVE-2024-12345" in md


def test_export_unknown_format_raises(tmp_path):
    with pytest.raises(ValueError):
        export_report([], META, "pdf", tmp_path / "report.pdf")
