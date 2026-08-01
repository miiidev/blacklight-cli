"""Host risk scoring: a transparent 0-100 formula per host."""

from blacklight.cve_matcher import Finding

SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 10,
    "medium": 4,
    "low": 1,
    "unknown": 0,
}
MAX_BASE = 60
KEV_BONUS = 10
MAX_KEV_BONUS = 20
MAX_EPSS_BONUS = 10


def host_risk_score(findings: list[Finding]) -> float:
    """Score a host 0-100 from its findings.

    base = sum of severity weights, capped at MAX_BASE
    + KEV_BONUS per KEV finding, capped at MAX_KEV_BONUS
    + (max EPSS among findings) * MAX_EPSS_BONUS
    total capped at 100.
    """
    base = min(sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings), MAX_BASE)
    kev_count = sum(1 for f in findings if f.in_kev)
    kev_bonus = min(kev_count * KEV_BONUS, MAX_KEV_BONUS)
    epss_values = [f.epss or 0.0 for f in findings]
    epss_bonus = (max(epss_values) if epss_values else 0.0) * MAX_EPSS_BONUS
    return round(min(base + kev_bonus + epss_bonus, 100), 1)


from blacklight.web.models import WebFinding


def web_risk_score(findings: list[WebFinding]) -> float:
    """Score a web target 0-100 from its findings (severity weights only)."""
    base = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return round(min(base, 100), 1)
