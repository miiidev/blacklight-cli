"""Web scan orchestration: run checks + fingerprint CVEs into WebFindings."""

import os
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

from blacklight import enrichment, guardrails
from blacklight.cpe_map import service_to_cpe
from blacklight.cve_matcher import Finding, NvdClient, build_findings
from blacklight.scanner import ScanRecord
from blacklight.web import http
from blacklight.web.checks import CHECKS
from blacklight.web.fingerprint import Fingerprint, fingerprint_page
from blacklight.web.models import WebFinding


@dataclass
class WebResult:
    """Outcome of a web scan: findings plus run metadata."""

    findings: list[WebFinding]
    meta: dict


def port_for_url(url: str) -> int:
    """Default port for a URL: explicit port, else 443/80 by scheme."""
    parsed = urllib.parse.urlparse(url)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _hostname(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""


def _cve_findings(url: str, host: str, page: http.Page, no_cache: bool) -> list[WebFinding]:
    fingerprints = fingerprint_page(page)
    if not fingerprints:
        return []
    client = NvdClient(api_key=os.environ.get("BLACKLIGHT_NVD_KEY"), no_cache=no_cache)
    matched: list[Finding] = []
    for fp in fingerprints:
        cpe = service_to_cpe(fp.service, fp.version)
        if cpe is None:
            continue
        record = ScanRecord(host=host, port=port_for_url(url), protocol="tcp",
                            service=fp.service, version=fp.version)
        matched.extend(build_findings([record], client))
    enrichment.enrich_findings(matched)
    return [
        WebFinding(url=page.url, category="fingerprint", detail=f.description,
                   severity=f.severity, evidence=f.cpe,
                   cve_id=f.cve_id, epss=f.epss, in_kev=f.in_kev)
        for f in matched
    ]


def run_web_scan(url: str, timeout: int = 30, no_cache: bool = False) -> WebResult:
    """Fetch the page, run all checks, fingerprint CVEs, return findings + meta."""
    page = http.fetch_page(url, timeout)
    findings: list[WebFinding] = []
    errored = 0

    def probe(target_url: str, params: dict | None = None):
        return http.probe(target_url, params, timeout)

    for name, check in CHECKS.items():
        try:
            finding = check(page, probe)
        except Exception:
            errored += 1
            continue
        if finding is not None:
            findings.append(finding)

    host = _hostname(page.url)
    resolved = guardrails.resolve_hostname(host) or host
    findings.extend(_cve_findings(url, resolved, page, no_cache))
    meta = {
        "url": url,
        "host": host,
        "resolved_ip": resolved,
        "checks_run": len(CHECKS),
        "checks_errored": errored,
        "cve_findings": sum(1 for f in findings if f.category == "fingerprint"),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return WebResult(findings=findings, meta=meta)
