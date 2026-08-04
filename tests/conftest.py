import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def nmap_xml() -> str:
    return (FIXTURES / "nmap_sv.xml").read_text(encoding="utf-8")


@pytest.fixture
def nvd_payload() -> dict:
    return json.loads((FIXTURES / "nvd_cves.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def isolated_history_db(monkeypatch, tmp_path):
    """Keep history.db out of the real ~/.blacklight during tests."""
    monkeypatch.setattr("blacklight.paths.HISTORY_DB", tmp_path / "history.db")
