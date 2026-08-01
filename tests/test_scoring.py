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
