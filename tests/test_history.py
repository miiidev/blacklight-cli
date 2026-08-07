import sqlite3

import pytest
from rich.console import Console

from blacklight import paths
from blacklight.cve_matcher import Finding
from blacklight.history import (
    diff_for_target,
    latest_scan,
    list_recent,
    record_scan,
    render_diff,
    render_list,
    render_trend,
    trend_for_target,
)
from blacklight.tls import TlsFinding
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


def _scan_result(kind, target, generated, findings, services=2):
    from blacklight.engine import NetworkMeta, ScanResult, WebMeta

    findings = findings or []
    if kind == "scan":
        meta = NetworkMeta(targets=target, hosts_scanned=1,
                           services_found=services,
                           findings_count=len(findings), generated=generated)
        return ScanResult(kind=kind, target=target, generated=generated,
                          findings=findings, web_findings=[], meta=meta)
    meta = WebMeta(url=target, host="example.com", resolved_ip="1.2.3.4",
                   checks_run=1, checks_errored=0, cve_findings=len(findings),
                   generated=generated)
    return ScanResult(kind=kind, target=target, generated=generated,
                      findings=[], web_findings=findings, meta=meta)


def test_record_scan_network_stores_scan_and_findings():
    record_scan(_scan_result("scan", "192.168.1.10", NET_META["generated"],
                             [net_finding(in_kev=True),
                              net_finding(port=80, service="httpd", cve_id="")]),
                False)
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
    record_scan(_scan_result("web", "https://example.com",
                             WEB_META["generated"], [finding]),
                True)
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
    record_scan(_scan_result("scan", "a.local", "2026-08-01T00:00:00+00:00", []), False)
    record_scan(_scan_result("scan", "b.local", "2026-08-02T00:00:00+00:00", []), False)
    record_scan(_scan_result("scan", "c.local", "2026-08-03T00:00:00+00:00", []), False)
    rows = list_recent(limit=2)
    assert [r.target for r in rows] == ["c.local", "b.local"]
    rows = list_recent()
    assert [r.target for r in rows] == ["c.local", "b.local", "a.local"]


def test_list_recent_empty_returns_no_rows():
    assert list_recent() == []


def test_record_creates_db_at_paths_history_db():
    record_scan(_scan_result("scan", "x.local", NET_META["generated"], []), False)
    assert paths.HISTORY_DB.exists()


def _record_scan_at(kind, target, generated, findings, permission=False):
    record_scan(_scan_result(kind, target, generated, findings), permission)


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


def test_trend_network_max_host_score_oldest_first():
    _record_scan_at("scan", "192.168.1.0/24", "2026-08-01T00:00:00+00:00",
                    [net_finding(severity="medium")])
    _record_scan_at("scan", "192.168.1.0/24", "2026-08-02T00:00:00+00:00",
                    [net_finding(severity="low"),
                     net_finding(host="192.168.1.20", severity="critical",
                                 in_kev=True, epss=0.9)])
    points = trend_for_target("192.168.1.0/24")
    assert [p.scanned_at for p in points] == [
        "2026-08-01T00:00:00+00:00", "2026-08-02T00:00:00+00:00"]
    assert points[0].score < points[1].score


def test_trend_host_filter_limits_to_one_host():
    _record_scan_at("scan", "192.168.1.0/24", "2026-08-02T00:00:00+00:00",
                    [net_finding(severity="low"),
                     net_finding(host="192.168.1.20", severity="critical",
                                 in_kev=True, epss=0.9)])
    points = trend_for_target("192.168.1.0/24", host="192.168.1.20")
    assert len(points) == 1
    assert points[0].score == 39.0


def test_trend_clean_network_scan_scores_zero():
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00", [])
    points = trend_for_target("192.168.1.10")
    assert len(points) == 1
    assert points[0].score == 0.0


def test_trend_web_uses_web_risk_score():
    f1 = WebFinding(url="https://example.com", category="missing_headers",
                    detail="A", severity="medium", evidence="")
    _record_scan_at("web", "https://example.com", "2026-08-01T00:00:00+00:00", [f1])
    _record_scan_at("web", "https://example.com", "2026-08-02T00:00:00+00:00", [])
    points = trend_for_target("https://example.com")
    assert points[0].score == 4.0
    assert points[1].score == 0.0


def test_trend_limit_caps_points():
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding()])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [net_finding()])
    _record_scan_at("scan", "192.168.1.10", "2026-08-03T00:00:00+00:00",
                    [net_finding()])
    points = trend_for_target("192.168.1.10", limit=2)
    assert len(points) == 2
    assert points[0].scanned_at == "2026-08-02T00:00:00+00:00"


def test_trend_unknown_target_returns_none():
    assert trend_for_target("10.0.0.99") is None


def test_render_list_empty_warns(capsys):
    render_list([], Console(width=200))
    assert "No scan history yet. Run a scan first." in capsys.readouterr().out


def test_render_list_shows_columns_and_permission(capsys):
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [net_finding()], permission=True)
    render_list(list_recent(), Console(width=200))
    out = capsys.readouterr().out
    assert "KIND" in out
    assert "192.168.1.10" in out
    assert "yes" in out


def test_render_diff_no_previous_warns(capsys):
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding()])
    render_diff(diff_for_target("192.168.1.10"), Console(width=200))
    assert "No previous scan of 192.168.1.10" in capsys.readouterr().out


def test_render_diff_shows_score_delta_and_findings(capsys):
    low = net_finding(severity="low", in_kev=False, epss=0.0)
    crit = net_finding(port=443, service="nginx", cve_id="CVE-2024-9999",
                       severity="critical", in_kev=True, epss=0.9)
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00", [low])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [low, crit])
    render_diff(diff_for_target("192.168.1.10"), Console(width=200))
    out = capsys.readouterr().out
    assert "Risk score:" in out
    assert "worsened" in out
    assert "CVE-2024-9999" in out
    assert "Plus 1 unchanged finding(s)" in out


def test_render_diff_verbose_lists_unchanged(capsys):
    low = net_finding(severity="low", in_kev=False, epss=0.0)
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00", [low])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00", [low])
    render_diff(diff_for_target("192.168.1.10"), Console(width=200), verbose=True)
    out = capsys.readouterr().out
    assert "Unchanged findings" in out
    assert "OpenSSH" in out


def test_render_trend_shows_gauge_and_scores(capsys):
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding(severity="medium")])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00", [])
    render_trend(trend_for_target("192.168.1.10"), Console(width=200),
                 target="192.168.1.10")
    out = capsys.readouterr().out
    assert "Risk trend for 192.168.1.10" in out
    assert "9.0" in out
    assert "0.0" in out


def _tls_result():
    from blacklight.engine import NetworkMeta, ScanResult

    meta = NetworkMeta(targets="192.168.1.10", hosts_scanned=1, services_found=1,
                       findings_count=0, tls_findings_count=1,
                       generated="2026-08-04T10:00:00+00:00")
    return ScanResult(
        kind="scan", target="192.168.1.10", generated="2026-08-04T10:00:00+00:00",
        findings=[], web_findings=[], meta=meta,
        tls_findings=[TlsFinding(host="192.168.1.10", port=443, service="https",
                                 category="protocol", detail="supports SSLv3",
                                 evidence="SSLv3", severity="high",
                                 cve_id="TLS-PROTO-SSLV3")])


def test_record_scan_stores_tls_rows():
    record_scan(_tls_result(), False)
    conn = sqlite3.connect(paths.HISTORY_DB)
    rows = conn.execute(
        "SELECT fingerprint, category, severity, cvss, epss, in_kev, cve_id"
        " FROM findings"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    fingerprint, category, severity, cvss, epss, in_kev, cve_id = rows[0]
    assert fingerprint == "192.168.1.10|443|https|TLS-PROTO-SSLV3"
    assert category == "tls"
    assert severity == "high"
    assert cvss is None
    assert epss == 0.0
    assert in_kev == 0


def test_tls_rows_feed_diff_and_score():
    baseline = _scan_result("scan", "192.168.1.10", "2026-08-03T10:00:00+00:00", [],
                            services=1)
    record_scan(baseline, False)
    later = _tls_result()
    later.generated = "2026-08-04T11:00:00+00:00"
    later.meta.generated = "2026-08-04T11:00:00+00:00"
    record_scan(later, False)
    diff = diff_for_target("192.168.1.10")
    assert diff is not None and diff.new
    tls_new = [f for f in diff.new if f.category == "tls"]
    assert len(tls_new) == 1
    assert tls_new[0].severity == "high"
    assert diff.score_after > diff.score_before
