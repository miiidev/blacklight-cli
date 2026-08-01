from pathlib import Path

import pytest

from blacklight.cve_matcher import (
    CVE,
    Finding,
    NvdClient,
    build_findings,
    severity_from_score,
)
from blacklight.scanner import ScanRecord


def test_severity_from_score():
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(9.0) == "critical"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(4.0) == "medium"
    assert severity_from_score(1.2) == "low"
    assert severity_from_score(None) == "unknown"


def test_nvd_lookup_parses_payload(nvd_payload, tmp_path, monkeypatch):
    client = NvdClient(cache_dir=tmp_path)

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return nvd_payload

    monkeypatch.setattr(client.session, "get", lambda *a, **k: FakeResponse())
    cves = client.lookup("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*")
    assert [c.cve_id for c in cves] == ["CVE-2024-12345", "CVE-2023-99999"]
    assert cves[0].cvss_score == 9.8
    assert cves[0].severity == "critical"
    assert cves[0].fixed_version == "9.7"
    assert cves[1].severity == "medium"


def test_nvd_lookup_uses_cache(tmp_path, monkeypatch):
    client = NvdClient(cache_dir=tmp_path)
    cache_file = tmp_path / "nvd_cpe_2.3_a_openbsd_openssh_9.6_star_star_star_star_star_star_star.json"
    cache_file.write_text(
        '{"fetched_at": "2030-01-01T00:00:00+00:00", "cves": [{"cve_id": "CVE-2024-12345", '
        '"description": "cached", "cvss_score": 9.8, "severity": "critical", "fixed_version": null}]}'
    )

    def fail(*args, **kwargs):
        raise AssertionError("network should not be hit when cache is fresh")

    monkeypatch.setattr(client.session, "get", fail)
    cves = client.lookup("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*")
    assert cves[0].cve_id == "CVE-2024-12345"


def test_extract_fixed_version_list_shape():
    from blacklight.cve_matcher import _extract_fixed_version

    configs = [
        {"nodes": [{"cpeMatch": [{"vulnerable": True, "versionEndExcluding": "9.7"}]}]},
        {"nodes": [{"cpeMatch": [{"vulnerable": True, "versionEndExcluding": "9.6"}]}]},
    ]
    assert _extract_fixed_version(configs) == "9.6"
    assert _extract_fixed_version(configs[0]) == "9.7"
    assert _extract_fixed_version(None) is None


def test_nvd_lookup_rate_limits(tmp_path, monkeypatch):
    client = NvdClient(cache_dir=tmp_path)
    calls = []

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr(client.session, "get", lambda *a, **k: calls.append(1) or FakeResponse())
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr("blacklight.cve_matcher.time.sleep", fake_sleep)
    client.lookup("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*")
    client.lookup("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*")
    assert len(calls) == 2
    assert len(sleeps) == 1
    assert 5.5 <= sleeps[0] <= 6.0


def test_build_findings_skips_unmapped_services(tmp_path):
    client = NvdClient(cache_dir=tmp_path)
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="custom-app", version="1.2.3")]
    findings = build_findings(records, client)
    assert findings == []


def test_build_findings_returns_findings(tmp_path, nvd_payload, monkeypatch):
    client = NvdClient(cache_dir=tmp_path)

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return nvd_payload

    monkeypatch.setattr(client.session, "get", lambda *a, **k: FakeResponse())
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp", service="OpenSSH", version="9.6p1")]
    findings = build_findings(records, client)
    assert len(findings) == 2
    assert findings[0].host == "192.168.1.10"
    assert findings[0].port == 22
    assert findings[0].cve_id == "CVE-2024-12345"
    assert findings[0].cpe == "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"
