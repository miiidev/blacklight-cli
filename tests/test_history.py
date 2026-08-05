import sqlite3

import pytest

from blacklight import paths
from blacklight.cve_matcher import Finding
from blacklight.history import (
    diff_for_target,
    latest_scan,
    list_recent,
    record_scan,
)
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


def _record_scan_at(kind, target, generated, findings, permission=False):
    meta = dict(NET_META) if kind == "scan" else dict(WEB_META)
    meta["generated"] = generated
    meta["findings_count"] = len(findings)
    record_scan(kind, target, permission, meta, findings)


def test_parse_since_forms():
    from blacklight.history import _parse_since

    assert _parse_since("2026-08-01") == "2026-08-01T23:59:59+00:00"
    days = _parse_since("3d")
    assert days.endswith("+00:00")
    with pytest.raises(ValueError):
        _parse_since("nope")
    with pytest.raises(ValueError):
        _parse_since("abc")


def test_diff_identical_scans_have_no_changes():
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding()])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [net_finding()])
    result = diff_for_target("192.168.1.10")
    assert result.new == []
    assert result.fixed == []
    assert len(result.unchanged) == 1
    assert result.delta == 0.0
    assert result.delta_bucket == "unchanged"
    assert result.score_before == result.score_after


def test_diff_reports_new_findings_and_worsened():
    low = net_finding(severity="low", in_kev=False, epss=0.0)
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00", [low])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [low, net_finding(port=443, service="nginx",
                                      cve_id="CVE-2024-9999",
                                      severity="critical", in_kev=True, epss=0.9)])
    result = diff_for_target("192.168.1.10")
    assert result.delta_bucket == "worsened"
    assert result.delta > 0.05
    assert [r.fingerprint for r in result.new] == [
        "192.168.1.10|443|nginx|CVE-2024-9999"]
    assert result.fixed == []
    assert len(result.unchanged) == 1


def test_diff_reports_fixed_findings_and_improved():
    low = net_finding(severity="low", in_kev=False, epss=0.0)
    crit = net_finding(port=443, service="nginx", cve_id="CVE-2024-9999",
                       severity="critical", in_kev=True, epss=0.9)
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [low, crit])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00", [low])
    result = diff_for_target("192.168.1.10")
    assert result.delta_bucket == "improved"
    assert result.delta < -0.05
    assert result.new == []
    assert [r.fingerprint for r in result.fixed] == [
        "192.168.1.10|443|nginx|CVE-2024-9999"]
    assert len(result.unchanged) == 1


def test_diff_web_scans():
    f1 = WebFinding(url="https://example.com", category="missing_headers",
                    detail="A", severity="low", evidence="")
    f2 = WebFinding(url="https://example.com", category="missing_headers",
                    detail="B", severity="high", evidence="")
    _record_scan_at("web", "https://example.com", "2026-08-01T00:00:00+00:00", [f1])
    _record_scan_at("web", "https://example.com", "2026-08-02T00:00:00+00:00", [f2])
    result = diff_for_target("https://example.com")
    assert result.kind == "web"
    assert result.delta_bucket == "worsened"
    assert result.delta == 9.0
    assert [r.detail for r in result.new] == ["B"]
    assert [r.detail for r in result.fixed] == ["A"]
    assert result.unchanged == []


def test_diff_no_previous_scan():
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding()])
    result = diff_for_target("192.168.1.10")
    assert result.baseline_id is None
    assert result.score_before is None
    assert result.new == []
    assert result.delta_bucket == "unchanged"


def test_diff_unknown_target_returns_none():
    assert diff_for_target("10.0.0.99") is None


def test_diff_since_selects_older_baseline():
    a = net_finding(port=22, cve_id="CVE-2026-0001")
    b = net_finding(port=22, cve_id="CVE-2026-0002")
    c = net_finding(port=22, cve_id="CVE-2026-0003")
    _record_scan_at("scan", "192.168.1.10", "2025-12-30T00:00:00+00:00", [a])
    _record_scan_at("scan", "192.168.1.10", "2026-01-02T00:00:00+00:00", [b])
    _record_scan_at("scan", "192.168.1.10", "2026-01-15T00:00:00+00:00", [c])
    result = diff_for_target("192.168.1.10", since="2026-01-01")
    assert result.selected_id == latest_scan("scan", "192.168.1.10").id
    assert [r.cve_id for r in result.new] == ["CVE-2026-0003"]
    assert [r.cve_id for r in result.fixed] == ["CVE-2026-0001"]