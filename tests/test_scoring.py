from blacklight.cve_matcher import Finding
from blacklight.scoring import SEVERITY_WEIGHTS, host_risk_score


def _finding(severity="low", epss=0.0, in_kev=False) -> Finding:
    return Finding(
        host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
        cpe="cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", cve_id="CVE-2024-12345",
        description="desc", cvss_score=None, severity=severity,
        fixed_version=None, epss=epss, in_kev=in_kev,
    )


def test_weights_match_spec():
    assert SEVERITY_WEIGHTS == {"critical": 20, "high": 10, "medium": 4, "low": 1, "unknown": 0}


def test_empty_findings_score_zero():
    assert host_risk_score([]) == 0.0


def test_single_low_is_one():
    assert host_risk_score([_finding("low")]) == 1.0


def test_base_caps_at_60():
    findings = [_finding("critical") for _ in range(5)]
    assert host_risk_score(findings) == 60.0


def test_kev_bonus_capped_at_20():
    assert host_risk_score([_finding("high", in_kev=True), _finding("high", in_kev=True)]) == 40.0
    assert host_risk_score([_finding("high", in_kev=True) for _ in range(3)]) == 50.0


def test_epss_bonus_scales_with_max():
    assert host_risk_score([_finding("low", epss=1.0)]) == 11.0
    assert host_risk_score([_finding("low", epss=0.5)]) == 6.0
    assert host_risk_score([_finding("low", epss=0.0)]) == 1.0


def test_total_capped_at_100():
    findings = [
        _finding("critical", epss=1.0, in_kev=True),
        _finding("critical", epss=1.0, in_kev=True),
        _finding("critical", epss=1.0, in_kev=True),
        _finding("critical", epss=1.0, in_kev=True),
    ]
    assert host_risk_score(findings) == 90.0
    assert host_risk_score(findings) <= 100.0


from blacklight.scoring import web_risk_score
from blacklight.web.models import WebFinding


def test_web_risk_score_sums_severity_weights():
    findings = [
        WebFinding(url="u", category="sqli", detail="", severity="high", evidence=""),
        WebFinding(url="u", category="xss", detail="", severity="medium", evidence=""),
        WebFinding(url="u", category="security_header", detail="", severity="low", evidence=""),
    ]
    assert web_risk_score(findings) == 15.0  # 10 + 4 + 1


def test_web_risk_score_caps_at_100():
    findings = [
        WebFinding(url="u", category="sqli", detail="", severity="critical", evidence="")
        for _ in range(10)
    ]
    assert web_risk_score(findings) == 100.0


def test_web_risk_score_empty():
    assert web_risk_score([]) == 0.0


def test_host_risk_score_treats_none_epss_as_zero():
    f = Finding(host="h", port=80, service="s", version="v", cpe="c",
                cve_id="CVE-1", description="d", cvss_score=9.0,
                severity="critical", fixed_version=None, epss=None, in_kev=False)
    assert host_risk_score([f]) == 20.0
