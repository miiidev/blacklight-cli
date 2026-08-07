"""CVE matching via the NVD API 2.0 (CPE-based lookup) with local caching."""

import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from blacklight import paths
from blacklight.cpe_map import (
    cpe_to_match_string,
    extract_version,
    normalize_cpe,
    service_to_cpe,
)
from blacklight.scanner import ScanRecord

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_DAYS = 7
KEYED_REQUESTS_PER_SECOND = 50 / 30.0
UNKEYED_REQUESTS_PER_SECOND = 5 / 30.0


def severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to a severity label."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


@dataclass
class CVE:
    """A single vulnerability record from NVD."""

    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    fixed_version: str | None


@dataclass
class Finding:
    """A vulnerability matched to a specific host/port/service."""

    host: str
    port: int
    service: str
    version: str
    cpe: str
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    fixed_version: str | None
    epss: float | None = None
    in_kev: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class NvdClient:
    """NVD API client with disk cache and request throttling."""

    def __init__(
        self,
        api_key: str | None = None,
        cache_dir: Path | None = None,
        no_cache: bool = False,
    ):
        self.api_key = api_key
        self.cache_dir = cache_dir or paths.CACHE_DIR
        self.no_cache = no_cache
        self.session = requests.Session()
        rate = KEYED_REQUESTS_PER_SECOND if api_key else UNKEYED_REQUESTS_PER_SECOND
        self._min_interval = 1.0 / rate
        self._last_request = 0.0

    def lookup(self, cpe: str) -> list[CVE]:
        """Return CVEs affecting the given CPE, using cache when possible."""
        cached = self._load_cache(cpe)
        if cached is not None:
            return cached
        cves = self._fetch(cpe)
        self._save_cache(cpe, cves)
        return cves

    def _fetch(self, cpe: str) -> list[CVE]:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        resp = self.session.get(
            NVD_API_URL,
            params={"virtualMatchString": cpe_to_match_string(cpe), "resultsPerPage": 100},
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 403:
            raise RuntimeError("NVD API returned 403 - check your BLACKLIGHT_NVD_KEY.")
        resp.raise_for_status()
        return [_parse_cve(item) for item in resp.json().get("vulnerabilities", [])]

    def _cache_path(self, cpe: str) -> Path:
        safe = cpe.replace(":", "_").replace("/", "_").replace("*", "star")
        return self.cache_dir / f"nvd_{safe}.json"

    def _load_cache(self, cpe: str) -> list[CVE] | None:
        if self.no_cache:
            return None
        path = self._cache_path(cpe)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            fetched = datetime.fromisoformat(data["fetched_at"])
            if datetime.now(timezone.utc) - fetched > timedelta(days=CACHE_TTL_DAYS):
                return None
            return [CVE(**item) for item in data["cves"]]
        except (ValueError, KeyError, TypeError, OSError):
            return None

    def _save_cache(self, cpe: str, cves: list[CVE]) -> None:
        path = self._cache_path(cpe)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cpe": cpe,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "cves": [asdict(c) for c in cves],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _parse_cve(item: dict) -> CVE:
    cve = item["cve"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    score, base_severity = _extract_cvss(cve.get("metrics", {}))
    return CVE(
        cve_id=cve["id"],
        description=description,
        cvss_score=score,
        severity=(base_severity or "").lower() or severity_from_score(score),
        fixed_version=_extract_fixed_version(cve.get("configurations")),
    )


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        return float(data["baseScore"]), data.get("baseSeverity") or data.get("severity")
    return None, None


def _extract_fixed_version(configurations: dict | list | None) -> str | None:
    """Best-effort fixed version from NVD configurations.

    Returns the smallest versionEndExcluding (or versionEndIncluding) found.
    NVD API 2.0 returns configurations either as an object with "nodes"
    or as a list of such objects; handle both.
    """
    if not configurations:
        return None
    nodes: list[dict] = []
    if isinstance(configurations, list):
        for item in configurations:
            if isinstance(item, dict):
                nodes.extend(item.get("nodes", []))
    else:
        nodes = configurations.get("nodes", [])
    excluding: list[str] = []
    including: list[str] = []
    for node in nodes:
        for match in node.get("cpeMatch", []):
            if match.get("versionEndExcluding"):
                excluding.append(match["versionEndExcluding"])
            elif match.get("versionEndIncluding"):
                including.append(match["versionEndIncluding"])
    if excluding:
        return min(excluding)
    if including:
        return f"<={min(including)}"
    return None


def build_findings(records: list[ScanRecord], client: NvdClient) -> list[Finding]:
    """Match scan records against CVEs, returning one Finding per CVE hit."""
    findings: list[Finding] = []
    for record in records:
        version = extract_version(record.version)
        cpe = (
            record.cpe and normalize_cpe(record.cpe, record.version)
            or service_to_cpe(record.service, version)
        )
        if cpe is None:
            continue
        for cve in client.lookup(cpe):
            findings.append(
                Finding(
                    host=record.host,
                    port=record.port,
                    service=record.service,
                    version=record.version,
                    cpe=cpe,
                    cve_id=cve.cve_id,
                    description=cve.description,
                    cvss_score=cve.cvss_score,
                    severity=cve.severity,
                    fixed_version=cve.fixed_version,
                )
            )
    return findings
