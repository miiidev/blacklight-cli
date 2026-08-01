"""Web scanning findings: config bugs and fingerprint-backed CVEs."""

from dataclasses import dataclass


@dataclass
class WebFinding:
    """A single web check result or fingerprint CVE finding."""

    url: str
    category: str
    detail: str
    severity: str
    evidence: str
    cve_id: str = ""
    epss: float | None = None
    in_kev: bool = False

    def to_dict(self) -> dict:
        return {
            "type": "web",
            "url": self.url,
            "category": self.category,
            "detail": self.detail,
            "severity": self.severity,
            "evidence": self.evidence,
            "cve_id": self.cve_id,
            "epss": self.epss,
            "in_kev": self.in_kev,
        }
