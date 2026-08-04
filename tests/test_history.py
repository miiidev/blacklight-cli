import sqlite3

from blacklight import paths
from blacklight.cve_matcher import Finding
from blacklight.history import list_recent, record_scan
from blacklight.web.models import WebFinding

NET_META = {
    "hosts_scanned": 1,
    "services_found": 2,
    "findings_count": 2,
    "generated": "2026-08-04T10:00:00+00:00",
}

WEB_META = {
    "url": "https://example.com",
    "resolved_ip": "1.2.3.4",
    "checks_run": 1,
    "checks_errored": 0,
    "cve_findings": 0,
    "generated": "2026-08-04T11:00:00+00:00",
}


def net_finding(host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
                cve_id="CVE-2024-0001", severity="high", in_kev=False, epss=0.5):
    return Finding(
        host=host, port=port, service=service, version=version,
        cpe="cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*:*",
        cve_id=cve_id, description="test", cvss_score=8.1,
        severity=severity, fixed_version="9.7", in_kev=in_kev, epss=epss,
    )


def test_record_scan_network_stores_scan_and_findings():
    record_scan("scan", "192.168.1.10", False, NET_META,
                [net_finding(in_kev=True), net_finding(port=80, service="httpd", cve_id="")])
    rows = list_recent()
    assert len(rows) == 1
    record = rows[0]
    assert record.kind == "scan"
    assert record.target == "192.168.1.10"
    assert record.permission is False
    assert record.hosts == 1
    assert record.services == 2
    assert record.findings_count == 2
    assert record.scanned_at == "2026-08-04T10:00:00+00:00"
    conn = sqlite3.connect(paths.HISTORY_DB)
    rows = conn.execute(
        "SELECT fingerprint, cve_id, severity, epss, in_kev FROM findings"
    ).fetchall()
    conn.close()
    assert len(rows) == 2
    fingerprints = {row[0] for row in rows}
    assert "192.168.1.10|22|OpenSSH|CVE-2024-0001" in fingerprints
    assert "192.168.1.10|80|httpd|v:9.6p1" in fingerprints
    by_cve = {row[1]: row for row in rows}
    assert by_cve["CVE-2024-0001"][2] == "high"
    assert by_cve["CVE-2024-0001"][3] == 0.5
    assert by_cve["CVE-2024-0001"][4] == 1


def test_record_web_uses_web_fingerprint_and_zero_counts():
    finding = WebFinding(
        url="https://example.com", category="missing_headers",
        detail="X-Frame-Options not set", severity="medium",
        evidence="header absent", cve_id="CVE-2024-0002", epss=0.1, in_kev=True,
    )
    record_scan("web", "https://example.com", True, WEB_META, [finding])
    rows = list_recent()
    assert len(rows) == 1
    record = rows[0]
    assert record.kind == "web"
    assert record.target == "https://example.com"
    assert record.permission is True
    assert record.hosts == 0
    assert record.services == 0
    assert record.findings_count == 1
    assert record.scanned_at == "2026-08-04T11:00:00+00:00"
    conn = sqlite3.connect(paths.HISTORY_DB)
    rows = conn.execute(
        "SELECT fingerprint, category, detail, in_kev FROM findings"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "https://example.com|missing_headers|X-Frame-Options not set"
    assert rows[0][1] == "missing_headers"
    assert rows[0][2] == "X-Frame-Options not set"
    assert rows[0][3] == 1


def test_list_recent_orders_newest_first_and_limits():
    record_scan("scan", "a.local", False, dict(NET_META, generated="2026-08-01T00:00:00+00:00"), [])
    record_scan("scan", "b.local", False, dict(NET_META, generated="2026-08-02T00:00:00+00:00"), [])
    record_scan("scan", "c.local", False, dict(NET_META, generated="2026-08-03T00:00:00+00:00"), [])
    rows = list_recent(limit=2)
    assert [r.target for r in rows] == ["c.local", "b.local"]
    rows = list_recent()
    assert [r.target for r in rows] == ["c.local", "b.local", "a.local"]


def test_list_recent_empty_returns_no_rows():
    assert list_recent() == []


def test_record_creates_db_at_paths_history_db():
    record_scan("scan", "x.local", False, NET_META, [])
    assert paths.HISTORY_DB.exists()