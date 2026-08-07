"""Generate examples/sample_report.html + .md from sample findings."""

from pathlib import Path

from blacklight.cve_matcher import Finding
from blacklight.engine import NetworkMeta, ScanResult
from blacklight.reporter import export_report

SAMPLES = [
    Finding(host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
            cpe="cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*",
            cve_id="CVE-2024-6387", description="regreSSHion: remote code execution "
            "in OpenSSH server (signal handler race).", cvss_score=8.1,
            severity="high", fixed_version="9.7p1", epss=0.9999, in_kev=True),
    Finding(host="192.168.1.10", port=80, service="Apache httpd", version="2.4.54",
            cpe="cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*",
            cve_id="CVE-2023-25690", description="HTTP request smuggling in Apache "
            "httpd mod_proxy.", cvss_score=9.8, severity="critical",
            fixed_version="2.4.56", epss=0.95, in_kev=False),
    Finding(host="192.168.1.11", port=3306, service="MySQL", version="5.7.42",
            cpe="cpe:2.3:a:oracle:mysql:5.7.42:*:*:*:*:*:*:*",
            cve_id="CVE-2023-21912", description="Multiple unspecified "
            "vulnerabilities in MySQL Server.", cvss_score=4.9, severity="medium",
            fixed_version="5.7.43", epss=0.01, in_kev=False),
]

GENERATED = "2030-01-01T00:00:00+00:00"


def _result() -> ScanResult:
    meta = NetworkMeta(targets="192.168.1.0/24", hosts_scanned=2,
                       services_found=3, findings_count=len(SAMPLES),
                       generated=GENERATED)
    return ScanResult(kind="scan", target="192.168.1.0/24", generated=GENERATED,
                      findings=SAMPLES, web_findings=[], meta=meta)


def main() -> None:
    export_report(_result(), "html", Path(__file__).parent / "sample_report.html")
    export_report(_result(), "markdown", Path(__file__).parent / "sample_report.md")


if __name__ == "__main__":
    main()
