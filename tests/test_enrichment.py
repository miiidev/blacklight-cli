import json
from pathlib import Path

from blacklight.cve_matcher import Finding
from blacklight.enrichment import enrich_findings, fetch_epss_scores, load_kev_ids


def _finding(cve_id: str) -> Finding:
    return Finding(
        host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
        cpe="cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", cve_id=cve_id,
        description="desc", cvss_score=9.8, severity="critical",
        fixed_version=None,
    )


def test_fetch_epss_scores_queries_and_caches(tmp_path, monkeypatch):
    calls = []

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": [
                    {"cve": "CVE-2024-12345", "epss": "0.98765"},
                    {"cve": "CVE-2023-99999", "epss": "0.00123"},
                ]
            }

    monkeypatch.setattr(
        "blacklight.enrichment.requests.get",
        lambda *a, **k: calls.append(k) or FakeResponse(),
    )
    scores = fetch_epss_scores(["CVE-2024-12345", "CVE-2023-99999"], tmp_path)
    assert scores == {"CVE-2024-12345": 0.98765, "CVE-2023-99999": 0.00123}
    assert len(calls) == 1
    assert "cve" in calls[0]["params"]
    assert (tmp_path / "epss.json").exists()


def test_fetch_epss_scores_skips_network_when_cached(tmp_path, monkeypatch):
    (tmp_path / "epss.json").write_text(json.dumps({"CVE-2024-12345": "0.5"}))
    fail = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network hit"))  # noqa: E731
    monkeypatch.setattr("blacklight.enrichment.requests.get", fail)
    assert fetch_epss_scores(["CVE-2024-12345"], tmp_path) == {"CVE-2024-12345": 0.5}


def test_fetch_epss_scores_returns_zero_for_missing(tmp_path, monkeypatch):
    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"data": []}

    monkeypatch.setattr("blacklight.enrichment.requests.get", lambda *a, **k: FakeResponse())
    assert fetch_epss_scores(["CVE-2020-0001"], tmp_path) == {"CVE-2020-0001": 0.0}


def test_load_kev_ids_uses_fresh_cache(tmp_path, monkeypatch):
    cache_file = tmp_path / "kev.json"
    cache_file.write_text(
        json.dumps(
            {
                "fetched_at": "2030-01-01T00:00:00+00:00",
                "cve_ids": ["CVE-2024-12345"],
            }
        )
    )
    fail = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network hit"))  # noqa: E731
    monkeypatch.setattr("blacklight.enrichment.requests.get", fail)
    assert load_kev_ids(tmp_path) == {"CVE-2024-12345"}


def test_load_kev_ids_refreshes_stale_cache(tmp_path, monkeypatch):
    cache_file = tmp_path / "kev.json"
    cache_file.write_text(
        json.dumps(
            {
                "fetched_at": "2000-01-01T00:00:00+00:00",
                "cve_ids": ["CVE-2024-99999"],
            }
        )
    )

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}

    monkeypatch.setattr("blacklight.enrichment.requests.get", lambda *a, **k: FakeResponse())
    assert load_kev_ids(tmp_path) == {"CVE-2024-12345"}


def test_enrich_findings_sets_epss_and_kev(tmp_path, monkeypatch):
    (tmp_path / "kev.json").write_text(
        json.dumps(
            {
                "fetched_at": "2030-01-01T00:00:00+00:00",
                "cve_ids": ["CVE-2024-12345"],
            }
        )
    )

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"cve": "CVE-2024-12345", "epss": "0.9"}]}

    monkeypatch.setattr("blacklight.enrichment.requests.get", lambda *a, **k: FakeResponse())
    findings = enrich_findings([_finding("CVE-2024-12345"), _finding("CVE-2023-99999")], tmp_path)
    assert findings[0].epss == 0.9
    assert findings[0].in_kev is True
    assert findings[1].epss == 0.0
    assert findings[1].in_kev is False
