"""Enrich findings with EPSS exploitation probability and CISA KEV membership."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from blacklight import paths
from blacklight.cve_matcher import Finding

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BATCH_SIZE = 100
EPSS_MAX_AGE = timedelta(days=7)
KEV_MAX_AGE = timedelta(hours=24)


def fetch_epss_scores(cve_ids: list[str], cache_dir: Path | None = None) -> dict[str, float]:
    """Return {cve_id: probability} using the cached score when available.

    CVEs with no EPSS score in the response map to 0.0.
    """
    cache_dir = cache_dir or paths.CACHE_DIR
    cache_file = cache_dir / "epss.json"
    cached: dict[str, float] = {}
    if cache_file.exists():
        try:
            cached = {
                cve_id: float(score)
                for cve_id, score in json.loads(cache_file.read_text(encoding="utf-8")).items()
            }
        except (ValueError, TypeError, OSError):
            cached = {}
    missing = [cve_id for cve_id in cve_ids if cve_id not in cached]
    for start in range(0, len(missing), EPSS_BATCH_SIZE):
        batch = missing[start : start + EPSS_BATCH_SIZE]
        resp = requests.get(EPSS_API_URL, params={"cve": ",".join(batch)}, timeout=30)
        resp.raise_for_status()
        for item in resp.json().get("data", []):
            cached[item["cve"]] = float(item["epss"])
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(cached), encoding="utf-8")
    return {cve_id: cached.get(cve_id, 0.0) for cve_id in cve_ids}


def load_kev_ids(cache_dir: Path | None = None, force_refresh: bool = False) -> set[str]:
    """Return the set of CVE IDs in CISA's Known Exploited Vulnerabilities list.

    Downloads the feed when the cache is missing or older than 24 hours.
    """
    cache_dir = cache_dir or paths.CACHE_DIR
    cache_file = cache_dir / "kev.json"
    if not force_refresh and cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            fetched = datetime.fromisoformat(data["fetched_at"])
            if datetime.now(timezone.utc) - fetched <= KEV_MAX_AGE:
                return set(data["cve_ids"])
        except (ValueError, KeyError, TypeError, OSError):
            pass
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    cve_ids = {entry["cveID"] for entry in resp.json().get("vulnerabilities", [])}
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(
        json.dumps(
            {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "cve_ids": sorted(cve_ids),
            }
        ),
        encoding="utf-8",
    )
    return cve_ids


def enrich_findings(findings: list[Finding], cache_dir: Path | None = None) -> list[Finding]:
    """Set epss and in_kev on each finding; returns the same list."""
    if not findings:
        return findings
    scores = fetch_epss_scores([f.cve_id for f in findings], cache_dir)
    kev_ids = load_kev_ids(cache_dir)
    for finding in findings:
        finding.epss = scores.get(finding.cve_id, 0.0)
        finding.in_kev = finding.cve_id in kev_ids
    return findings
