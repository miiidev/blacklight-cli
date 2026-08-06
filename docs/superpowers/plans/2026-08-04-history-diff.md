# Scan History, Diffing, and Risk Trend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store every network and web scan in a local SQLite history database, then expose `blacklight history` / `history diff` / `history trend` CLI commands and matching console commands that diff findings between scans and show risk-score trends.

**Architecture:** One new leaf module `blacklight/history.py` owns the SQLite schema, recording, diff/trend queries, and rich rendering. `execute_scan`/`execute_web` in `blacklight/cli.py` call `history.record_scan(...)` right after logging (recording failures are non-fatal warnings). The CLI exposes a `history` typer sub-app; the console's `CommandRunner` adds `history`/`trend` commands that call the same `history` functions. Scoring reuses the existing `host_risk_score`/`web_risk_score` from `blacklight/scoring.py`, rebuilt from stored rows.

**Tech Stack:** Python 3.11+ stdlib `sqlite3`, rich `Table`, existing `blacklight/scoring.py` and `blacklight/theme.py` (`risk_gauge`, `SEVERITY_STYLE`), typer sub-apps, prompt_toolkit WordCompleter (no new dependencies).

## Global Constraints

- Scope is store + diffing + risk trend ONLY. No accept/suppress, no retention/pruning, no migration machinery (`PRAGMA user_version` is reserved, do not set it).
- Persistence: stdlib `sqlite3` at `blacklight.paths.HISTORY_DB` = `~/.blacklight/history.db`. NO new dependency.
- Both scan kinds are recorded and diffed: kind `"scan"` (network) and `"web"`.
- Both CLI (`blacklight history ...`) and console (`history`, `history <target>`, `trend <target>`) surface the SAME `blacklight/history.py` functions — no duplicate query/rendering logic.
- Diff baseline: immediately-previous scan of same kind+target; `--since Nd` or `--since YYYY-MM-DD` narrows the baseline to the newest scan at/before the cutoff (Nd → now minus N days, UTC; date → `T23:59:59+00:00` end of that day, UTC).
- Diff buckets by fingerprint set-difference: NEW / FIXED / UNCHANGED. UNCHANGED is collapsed to a count line unless `--verbose`.
- Score delta classification: delta > 0.05 → "worsened", delta < -0.05 → "improved", else "unchanged". Delta = round(score_after - score_before, 1).
- Fingerprints: network = `host|port|service|cve_id` (fallback `v:<version>` when `cve_id` empty); web = `url|category|detail`.
- Trend scores: network = max of `host_risk_score` per host in the scan (or the single host with `--host`); web = `web_risk_score`. Trend points rendered with `theme.risk_gauge`.
- Error matrix (exact text, exit codes): corrupt DB → `[red]History database error:[/] {exc}` exit 1; bad `--since` → red message + red usage line, exit 1; no scans of target at all → `[yellow]No scans of {target} yet.[/]` exit 0; one scan, no predecessor → `[yellow]No previous scan of {target}.[/]` exit 0; empty history list → `[yellow]No scan history yet. Run a scan first.[/]` exit 0.
- Recording failure (OSError, sqlite3.Error) → `[yellow]Could not record scan history:[/] {exc}` and the scan continues normally (exit code unaffected).
- Network target key stored in `scans.target` = `", ".join(sorted(targets))`. Web target = the normalized URL from `execute_web`.
- Version bumps to 0.3.0 in `pyproject.toml` and `blacklight/__init__.py`.
- Requires-Python >= 3.11 (`X | None` unions, `datetime.timezone.utc`, no `datetime.UTC`).
- Tests never touch the real `~/.blacklight/history.db` (autouse conftest fixture redirects it to tmp_path).

---

### Task 1: History database core (schema, record, list)

**Files:**
- Modify: `blacklight/paths.py:5-8` (add `HISTORY_DB` constant)
- Modify: `tests/conftest.py` (autouse isolation fixture)
- Create: `blacklight/history.py`
- Create: `tests/test_history.py`

**Interfaces:**
- Consumes: `blacklight.paths.HISTORY_DB` (must be read at call time, not import time, so tests can monkeypatch it); `blacklight.cve_matcher.Finding` (fields `host, port, service, version, cpe, cve_id, description, cvss_score, severity, fixed_version, epss, in_kev`); `blacklight.web.models.WebFinding` (fields `url, category, detail, severity, evidence, cve_id, epss, in_kev`).
- Produces: `blacklight.history.record_scan(kind: str, target: str, permission: bool, meta: dict, findings: list) -> None`; `blacklight.history.list_recent(limit: int = 20) -> list[ScanRecord]`; dataclasses `ScanRecord(id, kind, target, permission, scanned_at, hosts, services, findings_count)` and `FindingRecord(fingerprint, host, port, service, cve_id, category, detail, evidence, severity, cvss, epss, in_kev)`. Later tasks add functions to this same module.

- [ ] **Step 1: Add the isolation fixture to `tests/conftest.py`**

Append this fixture at the end of `tests/conftest.py` (after the existing `nvd_payload` fixture):

```python
@pytest.fixture(autouse=True)
def isolated_history_db(monkeypatch, tmp_path):
    """Keep history.db out of the real ~/.blacklight during tests."""
    monkeypatch.setattr("blacklight.paths.HISTORY_DB", tmp_path / "history.db")
```

- [ ] **Step 2: Add `HISTORY_DB` to `blacklight/paths.py`**

Change the block at the top of `blacklight/paths.py` from:

```python
HOME_DIR = Path.home() / ".blacklight"
CACHE_DIR = HOME_DIR / "cache"
SCAN_LOG = HOME_DIR / "scan.log"
CONSOLE_HISTORY = HOME_DIR / "console_history"
```

to:

```python
HOME_DIR = Path.home() / ".blacklight"
CACHE_DIR = HOME_DIR / "cache"
SCAN_LOG = HOME_DIR / "scan.log"
CONSOLE_HISTORY = HOME_DIR / "console_history"
HISTORY_DB = HOME_DIR / "history.db"
```

- [ ] **Step 3: Write the failing tests in `tests/test_history.py`**

```python
import sqlite3

from blacklight import paths
from blacklight.cve_matcher import Finding
from blacklight.history import list_recent, record_scan
from blacklight.web.models import WebFinding

NET_META = {
    "hosts_scanned": 1,
    "services_found": 2,
    "findings_count": 2,
    "generated": "2026-08-04T10:00:00+00:00",
}

WEB_META = {
    "url": "https://example.com",
    "resolved_ip": "1.2.3.4",
    "checks_run": 1,
    "checks_errored": 0,
    "cve_findings": 0,
    "generated": "2026-08-04T11:00:00+00:00",
}


def net_finding(host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
                cve_id="CVE-2024-0001", severity="high", in_kev=False, epss=0.5):
    return Finding(
        host=host, port=port, service=service, version=version,
        cpe="cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*:*",
        cve_id=cve_id, description="test", cvss_score=8.1,
        severity=severity, fixed_version="9.7", in_kev=in_kev, epss=epss,
    )


def test_record_scan_network_stores_scan_and_findings():
    record_scan("scan", "192.168.1.10", False, NET_META,
                [net_finding(), net_finding(port=80, service="httpd", cve_id="")])
    rows = list_recent()
    assert len(rows) == 1
    record = rows[0]
    assert record.kind == "scan"
    assert record.target == "192.168.1.10"
    assert record.permission is False
    assert record.hosts == 1
    assert record.services == 2
    assert record.findings_count == 2
    assert record.scanned_at == "2026-08-04T10:00:00+00:00"
    conn = sqlite3.connect(paths.HISTORY_DB)
    rows = conn.execute(
        "SELECT fingerprint, cve_id, severity, epss, in_kev FROM findings"
    ).fetchall()
    conn.close()
    assert len(rows) == 2
    fingerprints = {row[0] for row in rows}
    assert "192.168.1.10|22|OpenSSH|CVE-2024-0001" in fingerprints
    assert "192.168.1.10|80|httpd|v:" in fingerprints
    by_cve = {row[1]: row for row in rows}
    assert by_cve["CVE-2024-0001"][2] == "high"
    assert by_cve["CVE-2024-0001"][3] == 0.5
    assert by_cve["CVE-2024-0001"][4] == 1


def test_record_web_uses_web_fingerprint_and_zero_counts():
    finding = WebFinding(
        url="https://example.com", category="missing_headers",
        detail="X-Frame-Options not set", severity="medium",
        evidence="header absent", cve_id="CVE-2024-0002", epss=0.1, in_kev=True,
    )
    record_scan("web", "https://example.com", True, WEB_META, [finding])
    rows = list_recent()
    assert len(rows) == 1
    record = rows[0]
    assert record.kind == "web"
    assert record.target == "https://example.com"
    assert record.permission is True
    assert record.hosts == 0
    assert record.services == 0
    assert record.findings_count == 1
    assert record.scanned_at == "2026-08-04T11:00:00+00:00"
    conn = sqlite3.connect(paths.HISTORY_DB)
    rows = conn.execute(
        "SELECT fingerprint, category, detail, in_kev FROM findings"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "https://example.com|missing_headers|X-Frame-Options not set"
    assert rows[0][1] == "missing_headers"
    assert rows[0][2] == "X-Frame-Options not set"
    assert rows[0][3] == 1


def test_list_recent_orders_newest_first_and_limits():
    record_scan("scan", "a.local", False, dict(NET_META, generated="2026-08-01T00:00:00+00:00"), [])
    record_scan("scan", "b.local", False, dict(NET_META, generated="2026-08-02T00:00:00+00:00"), [])
    record_scan("scan", "c.local", False, dict(NET_META, generated="2026-08-03T00:00:00+00:00"), [])
    rows = list_recent(limit=2)
    assert [r.target for r in rows] == ["c.local", "b.local"]
    rows = list_recent()
    assert [r.target for r in rows] == ["c.local", "b.local", "a.local"]


def test_list_recent_empty_returns_no_rows():
    assert list_recent() == []


def test_record_creates_db_at_paths_history_db():
    record_scan("scan", "x.local", False, NET_META, [])
    assert paths.HISTORY_DB.exists()
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `python -m pytest tests/test_history.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blacklight.history'`

- [ ] **Step 5: Create `blacklight/history.py` with the core storage layer**

```python
"""Scan history persistence: SQLite storage of network and web scan findings."""

import sqlite3
from dataclasses import dataclass

from blacklight import paths
from blacklight.cve_matcher import Finding
from blacklight.web.models import WebFinding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    permission INTEGER NOT NULL,
    scanned_at TEXT NOT NULL,
    hosts INTEGER NOT NULL DEFAULT 0,
    services INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    service TEXT,
    cve_id TEXT,
    category TEXT,
    detail TEXT,
    evidence TEXT,
    severity TEXT NOT NULL,
    cvss REAL,
    epss REAL,
    in_kev INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_kind_target ON scans(kind, target, scanned_at);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
"""


@dataclass
class ScanRecord:
    id: int
    kind: str
    target: str
    permission: bool
    scanned_at: str
    hosts: int
    services: int
    findings_count: int


@dataclass
class FindingRecord:
    fingerprint: str
    host: str | None
    port: int | None
    service: str | None
    cve_id: str | None
    category: str | None
    detail: str | None
    evidence: str | None
    severity: str
    cvss: float | None
    epss: float | None
    in_kev: bool


def _connect() -> sqlite3.Connection:
    paths.HISTORY_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(paths.HISTORY_DB)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _network_fingerprint(f: Finding) -> str:
    ident = f.cve_id or f"v:{f.version}"
    return f"{f.host}|{f.port}|{f.service}|{ident}"


def _web_fingerprint(w: WebFinding) -> str:
    return f"{w.url}|{w.category}|{w.detail}"


def record_scan(kind: str, target: str, permission: bool,
                meta: dict, findings: list) -> None:
    """Persist one completed scan; findings are Finding or WebFinding rows."""
    conn = _connect()
    try:
        if kind == "scan":
            hosts, services = meta["hosts_scanned"], meta["services_found"]
            count = meta["findings_count"]
        else:
            hosts, services, count = 0, 0, len(findings)
        cur = conn.execute(
            "INSERT INTO scans (kind, target, permission, scanned_at, hosts,"
            " services, findings_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (kind, target, 1 if permission else 0, meta["generated"],
             hosts, services, count),
        )
        scan_id = cur.lastrowid
        for f in findings:
            if kind == "scan":
                values = (
                    scan_id, "scan", _network_fingerprint(f),
                    f.host, f.port, f.service or "", f.cve_id or "",
                    None, f.description, None, f.severity,
                    f.cvss_score, f.epss or 0.0, 1 if f.in_kev else 0,
                )
            else:
                values = (
                    scan_id, "web", _web_fingerprint(f),
                    None, None, None, f.cve_id or "",
                    f.category, f.detail, f.evidence, f.severity,
                    None, f.epss or 0.0, 1 if f.in_kev else 0,
                )
            conn.execute(
                "INSERT INTO findings (scan_id, kind, fingerprint, host, port,"
                " service, cve_id, category, detail, evidence, severity, cvss,"
                " epss, in_kev) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )
        conn.commit()
    finally:
        conn.close()


def _row_to_record(row: sqlite3.Row) -> ScanRecord:
    return ScanRecord(
        id=row["id"], kind=row["kind"], target=row["target"],
        permission=bool(row["permission"]), scanned_at=row["scanned_at"],
        hosts=row["hosts"], services=row["services"],
        findings_count=row["findings_count"],
    )


def list_recent(limit: int = 20) -> list[ScanRecord]:
    """Newest-first scan records (both kinds, any target)."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, kind, target, permission, scanned_at, hosts, services,"
            " findings_count FROM scans ORDER BY scanned_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [_row_to_record(row) for row in rows]
    finally:
        conn.close()
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_history.py -v`
Expected: 5 passed. (Other existing tests must still pass too: run `python -m pytest tests/test_cli.py tests/test_cli_web.py tests/test_console.py -q` — the autouse fixture only redirects `HISTORY_DB`, which nothing else touches yet.)

- [ ] **Step 7: Commit**

```bash
git add blacklight/paths.py blacklight/history.py tests/conftest.py tests/test_history.py
git commit -m "feat: SQLite scan history storage (record + list)"
```

---

### Task 2: Diff computation

**Files:**
- Modify: `blacklight/history.py` (add diff functions)
- Modify: `tests/test_history.py` (add diff tests)

**Interfaces:**
- Consumes: from Task 1 — `_connect`, `_row_to_record`, `list_recent`, `record_scan`, `ScanRecord`, `FindingRecord`; `blacklight.scoring.host_risk_score(findings: list[Finding])`, `blacklight.scoring.web_risk_score(findings: list[WebFinding])`.
- Produces: `kind_for_target(target: str) -> str | None`; `latest_scan(kind: str, target: str) -> ScanRecord | None`; `findings_for(scan_id: int) -> list[FindingRecord]`; `diff_for_target(target: str, *, since: str | None = None) -> DiffResult | None` (None = target never scanned); dataclass `DiffResult(target, kind, selected_id, baseline_id, new, fixed, unchanged, score_before, score_after, delta, delta_bucket)` where `new`/`fixed`/`unchanged` are `list[FindingRecord]`, `baseline_id: int | None`, `score_before: float | None`, `delta: float`, `delta_bucket: str` in {"worsened", "improved", "unchanged"}. Internal: `_parse_since`, `_scan_before`, `_score`, `_network_score`, `_web_score`.

- [ ] **Step 1: Write the failing tests (append to `tests/test_history.py`)**

Add `import pytest` to the imports at the top of the file (change `import sqlite3` to `import sqlite3\n\nimport pytest`), then append:

```python
def _record_scan_at(kind, target, generated, findings, permission=False):
    meta = dict(NET_META) if kind == "scan" else dict(WEB_META)
    meta["generated"] = generated
    meta["findings_count"] = len(findings)
    record_scan(kind, target, permission, meta, findings)


def test_parse_since_forms():
    from blacklight.history import _parse_since

    assert _parse_since("2026-08-01") == "2026-08-01T23:59:59+00:00"
    days = _parse_since("3d")
    assert days.endswith("+00:00")
    with pytest.raises(ValueError):
        _parse_since("nope")
    with pytest.raises(ValueError):
        _parse_since("abc")


def test_diff_identical_scans_have_no_changes():
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding()])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [net_finding()])
    result = diff_for_target("192.168.1.10")
    assert result.new == []
    assert result.fixed == []
    assert len(result.unchanged) == 1
    assert result.delta == 0.0
    assert result.delta_bucket == "unchanged"
    assert result.score_before == result.score_after


def test_diff_reports_new_findings_and_worsened():
    low = net_finding(severity="low", in_kev=False, epss=0.0)
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00", [low])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [low, net_finding(port=443, service="nginx",
                                      cve_id="CVE-2024-9999",
                                      severity="critical", in_kev=True, epss=0.9)])
    result = diff_for_target("192.168.1.10")
    assert result.delta_bucket == "worsened"
    assert result.delta > 0.05
    assert [r.fingerprint for r in result.new] == [
        "192.168.1.10|443|nginx|CVE-2024-9999"]
    assert result.fixed == []
    assert len(result.unchanged) == 1


def test_diff_reports_fixed_findings_and_improved():
    low = net_finding(severity="low", in_kev=False, epss=0.0)
    crit = net_finding(port=443, service="nginx", cve_id="CVE-2024-9999",
                       severity="critical", in_kev=True, epss=0.9)
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [low, crit])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00", [low])
    result = diff_for_target("192.168.1.10")
    assert result.delta_bucket == "improved"
    assert result.delta < -0.05
    assert result.new == []
    assert [r.fingerprint for r in result.fixed] == [
        "192.168.1.10|443|nginx|CVE-2024-9999"]
    assert len(result.unchanged) == 1


def test_diff_web_scans():
    f1 = WebFinding(url="https://example.com", category="missing_headers",
                    detail="A", severity="low", evidence="")
    f2 = WebFinding(url="https://example.com", category="missing_headers",
                    detail="B", severity="high", evidence="")
    _record_scan_at("web", "https://example.com", "2026-08-01T00:00:00+00:00", [f1])
    _record_scan_at("web", "https://example.com", "2026-08-02T00:00:00+00:00", [f2])
    result = diff_for_target("https://example.com")
    assert result.kind == "web"
    assert result.delta_bucket == "worsened"
    assert result.delta == 6.0
    assert [r.detail for r in result.new] == ["B"]
    assert [r.detail for r in result.fixed] == ["A"]
    assert result.unchanged == []


def test_diff_no_previous_scan():
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding()])
    result = diff_for_target("192.168.1.10")
    assert result.baseline_id is None
    assert result.score_before is None
    assert result.new == []
    assert result.delta_bucket == "unchanged"


def test_diff_unknown_target_returns_none():
    assert diff_for_target("10.0.0.99") is None


def test_diff_since_selects_older_baseline():
    a = net_finding(port=22, cve_id="CVE-2026-0001")
    b = net_finding(port=22, cve_id="CVE-2026-0002")
    c = net_finding(port=22, cve_id="CVE-2026-0003")
    _record_scan_at("scan", "192.168.1.10", "2025-12-30T00:00:00+00:00", [a])
    _record_scan_at("scan", "192.168.1.10", "2026-01-02T00:00:00+00:00", [b])
    _record_scan_at("scan", "192.168.1.10", "2026-01-15T00:00:00+00:00", [c])
    result = diff_for_target("192.168.1.10", since="2026-01-01")
    assert result.selected_id == latest_scan("scan", "192.168.1.10").id
    assert [r.cve_id for r in result.new] == ["CVE-2026-0003"]
    assert [r.cve_id for r in result.fixed] == ["CVE-2026-0001"]
```

Add the `diff_for_target` import to the import line in `tests/test_history.py`:

```python
from blacklight.history import (
    diff_for_target,
    latest_scan,
    list_recent,
    record_scan,
)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_history.py -v`
Expected: FAIL with `ImportError: cannot import name 'diff_for_target' from 'blacklight.history'`

- [ ] **Step 3: Add the diff layer to `blacklight/history.py`**

Extend the import block at the top of `blacklight/history.py`:

```python
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from blacklight import paths
from blacklight.cve_matcher import Finding
from blacklight.scoring import host_risk_score, web_risk_score
from blacklight.web.models import WebFinding
```

Append at the end of the file:

```python
@dataclass
class DiffResult:
    target: str
    kind: str
    selected_id: int
    baseline_id: int | None
    new: list[FindingRecord]
    fixed: list[FindingRecord]
    unchanged: list[FindingRecord]
    score_before: float | None
    score_after: float
    delta: float
    delta_bucket: str


def kind_for_target(target: str) -> str | None:
    """The kind ('scan' or 'web') of the most recent scan of this target."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT kind FROM scans WHERE target = ?"
            " ORDER BY scanned_at DESC, id DESC LIMIT 1",
            (target,),
        ).fetchone()
        return row["kind"] if row else None
    finally:
        conn.close()


def latest_scan(kind: str, target: str) -> ScanRecord | None:
    """The most recent scan record of this kind+target, or None."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id, kind, target, permission, scanned_at, hosts, services,"
            " findings_count FROM scans WHERE kind = ? AND target = ?"
            " ORDER BY scanned_at DESC, id DESC LIMIT 1",
            (kind, target),
        ).fetchone()
        return _row_to_record(row) if row else None
    finally:
        conn.close()


def findings_for(scan_id: int) -> list[FindingRecord]:
    """All stored findings of one scan, in insertion order."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT fingerprint, host, port, service, cve_id, category, detail,"
            " evidence, severity, cvss, epss, in_kev FROM findings"
            " WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        return [
            FindingRecord(
                fingerprint=r["fingerprint"], host=r["host"], port=r["port"],
                service=r["service"], cve_id=r["cve_id"], category=r["category"],
                detail=r["detail"], evidence=r["evidence"],
                severity=r["severity"], cvss=r["cvss"], epss=r["epss"],
                in_kev=bool(r["in_kev"]),
            )
            for r in rows
        ]
    finally:
        conn.close()


def _parse_since(since: str) -> str:
    """'Nd' -> cutoff now-N days (UTC); 'YYYY-MM-DD' -> end of that day (UTC)."""
    value = since.strip().lower()
    if value.endswith("d"):
        try:
            days = int(value[:-1])
        except ValueError as exc:
            raise ValueError(f"invalid --since value: {since}") from exc
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return cutoff.isoformat(timespec="seconds")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"invalid --since value: {since}") from exc
    return f"{value}T23:59:59+00:00"


def _scan_before(kind: str, target: str, *, since: str | None = None,
                 exclude_id: int) -> ScanRecord | None:
    """Newest scan of kind+target excluding exclude_id, at/before cutoff."""
    conn = _connect()
    try:
        sql = (
            "SELECT id, kind, target, permission, scanned_at, hosts, services,"
            " findings_count FROM scans WHERE kind = ? AND target = ? AND id != ?"
        )
        args: list = [kind, target, exclude_id]
        if since is not None:
            sql += " AND scanned_at <= ?"
            args.append(_parse_since(since))
        sql += " ORDER BY scanned_at DESC, id DESC LIMIT 1"
        row = conn.execute(sql, args).fetchone()
        return _row_to_record(row) if row else None
    finally:
        conn.close()


def _network_score(rows: list[FindingRecord]) -> float:
    findings = [
        Finding(host=r.host or "", port=r.port or 0, service=r.service or "",
                version="", cpe="", cve_id=r.cve_id or "", description="",
                cvss_score=r.cvss, severity=r.severity, fixed_version=None,
                epss=r.epss, in_kev=r.in_kev)
        for r in rows
    ]
    return host_risk_score(findings)


def _web_score(rows: list[FindingRecord]) -> float:
    findings = [
        WebFinding(url="", category=r.category or "", detail=r.detail or "",
                   severity=r.severity, evidence=r.evidence or "",
                   cve_id=r.cve_id or "", epss=r.epss, in_kev=r.in_kev)
        for r in rows
    ]
    return web_risk_score(findings)


def _score(kind: str, rows: list[FindingRecord]) -> float:
    return _network_score(rows) if kind == "scan" else _web_score(rows)


def diff_for_target(target: str, *, since: str | None = None) -> DiffResult | None:
    """Diff the latest scan of target against its previous scan.

    Returns None when the target has no recorded scans at all. When the
    latest scan has no predecessor, baseline_id is None.
    """
    kind = kind_for_target(target)
    if kind is None:
        return None
    latest = latest_scan(kind, target)
    baseline = _scan_before(kind, target, since=since, exclude_id=latest.id)
    selected = findings_for(latest.id)
    after = _score(kind, selected)
    if baseline is None:
        return DiffResult(
            target=target, kind=kind, selected_id=latest.id, baseline_id=None,
            new=[], fixed=[], unchanged=[],
            score_before=None, score_after=after, delta=0.0,
            delta_bucket="unchanged",
        )
    base = findings_for(baseline.id)
    before = _score(kind, base)
    base_fps = {r.fingerprint for r in base}
    sel_fps = {r.fingerprint for r in selected}
    new = [r for r in selected if r.fingerprint not in base_fps]
    fixed = [r for r in base if r.fingerprint not in sel_fps]
    unchanged = [r for r in selected if r.fingerprint in base_fps]
    delta = round(after - before, 1)
    if delta > 0.05:
        bucket = "worsened"
    elif delta < -0.05:
        bucket = "improved"
    else:
        bucket = "unchanged"
    return DiffResult(
        target=target, kind=kind, selected_id=latest.id, baseline_id=baseline.id,
        new=new, fixed=fixed, unchanged=unchanged,
        score_before=before, score_after=after, delta=delta,
        delta_bucket=bucket,
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_history.py -v`
Expected: 13 passed.

- [ ] **Step 5: Commit**

```bash
git add blacklight/history.py tests/test_history.py
git commit -m "feat: diff latest scan against previous by fingerprint"
```

---

### Task 3: Trend computation

**Files:**
- Modify: `blacklight/history.py` (add trend functions)
- Modify: `tests/test_history.py` (add trend tests)

**Interfaces:**
- Consumes: from Tasks 1-2 — `_connect`, `kind_for_target`, `Finding`, `WebFinding`, `host_risk_score`, `web_risk_score`.
- Produces: dataclass `TrendPoint(scan_id: int, scanned_at: str, score: float)`; `trend_for_target(target: str, *, host: str | None = None, limit: int = 50) -> list[TrendPoint] | None` (oldest-first; None = target never scanned; network score = max host score per scan, or the single host when `host` given; a network scan with no findings scores 0.0 and still appears; `host` has no effect when the target resolves to a web scan).

- [ ] **Step 1: Write the failing tests (append to `tests/test_history.py`)**

```python
def test_trend_network_max_host_score_oldest_first():
    _record_scan_at("scan", "192.168.1.0/24", "2026-08-01T00:00:00+00:00",
                    [net_finding(severity="medium")])
    _record_scan_at("scan", "192.168.1.0/24", "2026-08-02T00:00:00+00:00",
                    [net_finding(severity="low"),
                     net_finding(host="192.168.1.20", severity="critical",
                                 in_kev=True, epss=0.9)])
    points = trend_for_target("192.168.1.0/24")
    assert [p.scanned_at for p in points] == [
        "2026-08-01T00:00:00+00:00", "2026-08-02T00:00:00+00:00"]
    assert points[0].score < points[1].score


def test_trend_host_filter_limits_to_one_host():
    _record_scan_at("scan", "192.168.1.0/24", "2026-08-02T00:00:00+00:00",
                    [net_finding(severity="low"),
                     net_finding(host="192.168.1.20", severity="critical",
                                 in_kev=True, epss=0.9)])
    points = trend_for_target("192.168.1.0/24", host="192.168.1.20")
    assert len(points) == 1
    assert points[0].score > 50


def test_trend_clean_network_scan_scores_zero():
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00", [])
    points = trend_for_target("192.168.1.10")
    assert len(points) == 1
    assert points[0].score == 0.0


def test_trend_web_uses_web_risk_score():
    f1 = WebFinding(url="https://example.com", category="missing_headers",
                    detail="A", severity="medium", evidence="")
    _record_scan_at("web", "https://example.com", "2026-08-01T00:00:00+00:00", [f1])
    _record_scan_at("web", "https://example.com", "2026-08-02T00:00:00+00:00", [])
    points = trend_for_target("https://example.com")
    assert points[0].score == 4.0
    assert points[1].score == 0.0


def test_trend_limit_caps_points():
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding()])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [net_finding()])
    _record_scan_at("scan", "192.168.1.10", "2026-08-03T00:00:00+00:00",
                    [net_finding()])
    points = trend_for_target("192.168.1.10", limit=2)
    assert len(points) == 2
    assert points[0].scanned_at == "2026-08-02T00:00:00+00:00"


def test_trend_unknown_target_returns_none():
    assert trend_for_target("10.0.0.99") is None
```

Fix the odd assertion in `test_trend_host_filter_limits_to_one_host` by using this exact body instead:

```python
def test_trend_host_filter_limits_to_one_host():
    _record_scan_at("scan", "192.168.1.0/24", "2026-08-02T00:00:00+00:00",
                    [net_finding(severity="low"),
                     net_finding(host="192.168.1.20", severity="critical",
                                 in_kev=True, epss=0.9)])
    points = trend_for_target("192.168.1.0/24", host="192.168.1.20")
    assert len(points) == 1
    assert points[0].score > 50
```

(The critical+KEV+EPSS finding scores well above 50, so this asserts the filtered host — not the low host — drives the score.)

Update the import block in `tests/test_history.py` to add `trend_for_target`:

```python
from blacklight.history import (
    diff_for_target,
    latest_scan,
    list_recent,
    record_scan,
    trend_for_target,
)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_history.py -v`
Expected: FAIL with `ImportError: cannot import name 'trend_for_target' from 'blacklight.history'`

- [ ] **Step 3: Add the trend layer to `blacklight/history.py`**

Append at the end of the file:

```python
@dataclass
class TrendPoint:
    scan_id: int
    scanned_at: str
    score: float


def trend_for_target(target: str, *, host: str | None = None,
                     limit: int = 50) -> list[TrendPoint] | None:
    """Oldest-first risk scores per scan of target; None if never scanned.

    Network scans score as the max host_risk_score across the scan's hosts
    (or a single host when host is given). Scans without findings score 0.0.
    """
    kind = kind_for_target(target)
    if kind is None:
        return None
    conn = _connect()
    try:
        scan_rows = conn.execute(
            "SELECT id, scanned_at FROM scans WHERE kind = ? AND target = ?"
            " ORDER BY scanned_at DESC, id DESC LIMIT ?",
            (kind, target, limit),
        ).fetchall()
        points = []
        for sr in scan_rows:
            find_rows = conn.execute(
                "SELECT host, severity, epss, in_kev FROM findings"
                " WHERE scan_id = ? AND (? IS NULL OR host = ?)",
                (sr["id"], host, host),
            ).fetchall()
            if kind == "scan":
                by_host: dict[str, list[Finding]] = {}
                for fr in find_rows:
                    by_host.setdefault(fr["host"], []).append(
                        Finding(host=fr["host"], port=0, service="", version="",
                                cpe="", cve_id="", description="",
                                cvss_score=None, severity=fr["severity"],
                                fixed_version=None, epss=fr["epss"],
                                in_kev=bool(fr["in_kev"])))
                score = (max(host_risk_score(rows) for rows in by_host.values())
                         if by_host else 0.0)
            else:
                findings = [
                    WebFinding(url="", category="", detail="",
                               severity=fr["severity"], evidence="")
                    for fr in find_rows
                ]
                score = web_risk_score(findings)
            points.append(TrendPoint(sr["id"], sr["scanned_at"],
                                     round(score, 1)))
        points.reverse()
        return points
    finally:
        conn.close()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_history.py -v`
Expected: 19 passed.

- [ ] **Step 5: Commit**

```bash
git add blacklight/history.py tests/test_history.py
git commit -m "feat: risk score trend queries per target"
```

---

### Task 4: Rendering (shared by CLI and console)

**Files:**
- Modify: `blacklight/history.py` (add render functions)
- Modify: `tests/test_history.py` (add render tests)

**Interfaces:**
- Consumes: from Tasks 1-3 — `ScanRecord`, `DiffResult`, `TrendPoint`; `blacklight.theme.risk_gauge(score: float) -> str` (returns markup like `[green]███░░░░░░░[/] 30.0`), `blacklight.theme.SEVERITY_STYLE` (dict of severity -> rich style).
- Produces: `render_list(rows: list[ScanRecord], console: Console) -> None`; `render_diff(result: DiffResult, console: Console, *, verbose: bool = False) -> None`; `render_trend(points: list[TrendPoint], console: Console, *, target: str, host: str | None = None) -> None`. These print directly to the given rich `Console` (CLI passes the module console; console mode passes `Console(file=out)`).

- [ ] **Step 1: Write the failing tests (append to `tests/test_history.py`)**

```python
from rich.console import Console

from blacklight.history import (
    diff_for_target,
    latest_scan,
    list_recent,
    record_scan,
    render_diff,
    render_list,
    render_trend,
    trend_for_target,
)


def test_render_list_empty_warns(capsys):
    render_list([], Console())
    assert "No scan history yet. Run a scan first." in capsys.readouterr().out


def test_render_list_shows_columns_and_permission(capsys):
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [net_finding()], permission=True)
    render_list(list_recent(), Console())
    out = capsys.readouterr().out
    assert "KIND" in out
    assert "192.168.1.10" in out
    assert "yes" in out


def test_render_diff_no_previous_warns(capsys):
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding()])
    render_diff(diff_for_target("192.168.1.10"), Console())
    assert "No previous scan of 192.168.1.10" in capsys.readouterr().out


def test_render_diff_shows_score_delta_and_findings(capsys):
    low = net_finding(severity="low", in_kev=False, epss=0.0)
    crit = net_finding(port=443, service="nginx", cve_id="CVE-2024-9999",
                       severity="critical", in_kev=True, epss=0.9)
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00", [low])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00",
                    [low, crit])
    render_diff(diff_for_target("192.168.1.10"), Console())
    out = capsys.readouterr().out
    assert "Risk score:" in out
    assert "worsened" in out
    assert "CVE-2024-9999" in out
    assert "Plus 1 unchanged finding(s)" in out


def test_render_diff_verbose_lists_unchanged(capsys):
    low = net_finding(severity="low", in_kev=False, epss=0.0)
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00", [low])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00", [low])
    render_diff(diff_for_target("192.168.1.10"), Console(), verbose=True)
    out = capsys.readouterr().out
    assert "Unchanged findings" in out
    assert "OpenSSH" in out


def test_render_trend_shows_gauge_and_scores(capsys):
    _record_scan_at("scan", "192.168.1.10", "2026-08-01T00:00:00+00:00",
                    [net_finding(severity="medium")])
    _record_scan_at("scan", "192.168.1.10", "2026-08-02T00:00:00+00:00", [])
    render_trend(trend_for_target("192.168.1.10"), Console(),
                 target="192.168.1.10")
    out = capsys.readouterr().out
    assert "Risk trend for 192.168.1.10" in out
    assert "4.0" in out
    assert "0.0" in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_history.py -v`
Expected: FAIL with `ImportError: cannot import name 'render_list' from 'blacklight.history'`

- [ ] **Step 3: Add the render layer to `blacklight/history.py`**

Extend the import block at the top:

```python
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from rich.console import Console
from rich.table import Table

from blacklight import paths, theme
from blacklight.cve_matcher import Finding
from blacklight.scoring import host_risk_score, web_risk_score
from blacklight.web.models import WebFinding
```

Append at the end of the file:

```python
def _severity_cell(severity: str) -> str:
    style = theme.SEVERITY_STYLE.get(severity, "dim")
    return f"[{style}]{severity}[/]"


def _finding_table(title: str, rows: list[FindingRecord], kind: str) -> Table:
    table = Table(title=title)
    if kind == "scan":
        table.add_column("HOST")
        table.add_column("PORT", justify="right")
        table.add_column("SERVICE")
        table.add_column("CVE ID")
        table.add_column("SEVERITY")
        table.add_column("CVSS", justify="right")
        table.add_column("EPSS", justify="right")
        table.add_column("KEV")
        for r in rows:
            table.add_row(
                r.host or "", str(r.port or ""), r.service or "", r.cve_id or "",
                _severity_cell(r.severity), f"{r.cvss or 0:.1f}",
                f"{r.epss or 0:.2f}", "yes" if r.in_kev else "",
            )
    else:
        table.add_column("CATEGORY")
        table.add_column("DETAIL")
        table.add_column("SEVERITY")
        table.add_column("EVIDENCE")
        table.add_column("CVE ID")
        table.add_column("EPSS", justify="right")
        table.add_column("KEV")
        for r in rows:
            table.add_row(
                r.category or "", r.detail or "", _severity_cell(r.severity),
                r.evidence or "", r.cve_id or "", f"{r.epss or 0:.2f}",
                "yes" if r.in_kev else "",
            )
    return table


def render_list(rows: list[ScanRecord], console: Console) -> None:
    if not rows:
        console.print("[yellow]No scan history yet. Run a scan first.[/]")
        return
    table = Table(title="Recent scans (newest first)")
    table.add_column("ID", justify="right")
    table.add_column("KIND")
    table.add_column("TARGET")
    table.add_column("PERMISSION")
    table.add_column("HOSTS", justify="right")
    table.add_column("SERVICES", justify="right")
    table.add_column("FINDINGS", justify="right")
    table.add_column("SCANNED AT (UTC)", justify="right")
    for r in rows:
        table.add_row(
            str(r.id), r.kind, r.target,
            "[green]yes[/]" if r.permission else "[red]no[/]",
            str(r.hosts), str(r.services), str(r.findings_count), r.scanned_at,
        )
    console.print(table)


def render_diff(result: DiffResult, console: Console, *,
                verbose: bool = False) -> None:
    if result.baseline_id is None:
        console.print(f"[yellow]No previous scan of {result.target}.[/]")
        return
    console.print(f"{result.kind} target [bold]{result.target}[/] - "
                  f"latest scan #{result.selected_id}")
    sign = "+" if result.delta >= 0 else ""
    bucket = {
        "worsened": "[bold red]worsened[/]",
        "improved": "[green]improved[/]",
        "unchanged": "unchanged",
    }[result.delta_bucket]
    console.print(f"Risk score: {result.score_before:.1f} -> "
                  f"{result.score_after:.1f} ({sign}{result.delta:.1f}, "
                  f"{bucket})")
    if result.new:
        console.print(_finding_table("New findings", result.new, result.kind))
    else:
        console.print("[green]No new findings.[/]")
    if result.fixed:
        console.print(_finding_table("Fixed findings", result.fixed, result.kind))
    else:
        console.print("[green]No fixed findings.[/]")
    if result.unchanged:
        if verbose:
            console.print(_finding_table("Unchanged findings",
                                         result.unchanged, result.kind))
        else:
            console.print(f"[dim]Plus {len(result.unchanged)} unchanged "
                          f"finding(s).[/]")


def render_trend(points: list[TrendPoint], console: Console, *,
                 target: str, host: str | None = None) -> None:
    if not points:
        console.print(f"[yellow]No scans of {target} yet.[/]")
        return
    title = f"Risk trend for {target}"
    if host:
        title += f" (host: {host})"
    table = Table(title=title)
    table.add_column("SCAN ID", justify="right")
    table.add_column("SCANNED AT (UTC)", justify="right")
    table.add_column("RISK SCORE")
    for p in points:
        table.add_row(str(p.scan_id), p.scanned_at, theme.risk_gauge(p.score))
    console.print(table)
    console.print("[dim]Oldest scan at the top; newest at the bottom.[/]")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_history.py -v`
Expected: 25 passed.

- [ ] **Step 5: Commit**

```bash
git add blacklight/history.py tests/test_history.py
git commit -m "feat: render history list, diff, and trend via rich"
```

---

### Task 5: CLI wiring (history sub-app + record hooks)

**Files:**
- Modify: `blacklight/cli.py` (imports, record hooks, history handlers + typer sub-app)
- Modify: `tests/test_cli.py` (add history CLI tests)

**Interfaces:**
- Consumes: from Tasks 1-4 — `blacklight.history.list_recent`, `record_scan`, `diff_for_target`, `trend_for_target`, `render_list`, `render_diff`, `render_trend`; `blacklight.console` (already wired via `_console_command`); existing `execute_scan`/`execute_web`.
- Produces: typer sub-app `history_app` registered as `history` on `app` with commands `diff <target> [--since] [--verbose]` and `trend <target> [--host] [--limit]`; bare `blacklight history` lists recent scans (exit 0). `execute_scan`/`execute_web` now record history. Helper functions `_history_list() -> int`, `_history_diff(target, since, verbose) -> int`, `_history_trend(target, host, limit) -> int` returning process exit codes.

- [ ] **Step 1: Write the failing tests (append to `tests/test_cli.py`)**

```python
def test_execute_scan_records_history(monkeypatch, tmp_path):
    records = [ScanRecord(host="192.168.1.10", port=22, protocol="tcp",
                          service="OpenSSH", version="9.6p1")]
    monkeypatch.setattr("blacklight.cli.scanner.scan_hosts", lambda *a, **k: records)
    monkeypatch.setattr("blacklight.cli.scanner.find_nmap", lambda: "nmap")
    monkeypatch.setattr("blacklight.cli.os.environ", {})
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def lookup(self, cpe):
            return []

    monkeypatch.setattr("blacklight.cli.NvdClient", FakeClient)
    monkeypatch.setattr("blacklight.cli.enrichment.enrich_findings",
                        lambda findings, **k: findings)
    from blacklight import history
    assert history.list_recent() == []
    code = execute_scan(["192.168.1.10"], ports="22", timeout=30, no_cache=False,
                        output=None, fmt="html",
                        permission_granted=False, confirm=never_confirm)
    assert code == 0
    rows = history.list_recent()
    assert len(rows) == 1
    assert rows[0].kind == "scan"
    assert rows[0].target == "192.168.1.10"
    assert rows[0].hosts == 1
    assert rows[0].findings_count == 0


def test_execute_web_records_history(monkeypatch, tmp_path):
    monkeypatch.setattr("blacklight.cli.run_web_scan",
                        lambda *a, **k: SimpleNamespace(findings=[], meta=WEB_META))
    monkeypatch.setattr("blacklight.cli.paths.CACHE_DIR", tmp_path)
    monkeypatch.setattr("blacklight.cli.paths.SCAN_LOG", tmp_path / "scan.log")
    from blacklight import history
    code = execute_web("http://127.0.0.1", timeout=30, no_cache=False,
                       output=None, fmt="html",
                       permission_granted=False, confirm=never_confirm)
    assert code == 0
    rows = history.list_recent()
    assert len(rows) == 1
    assert rows[0].kind == "web"
    assert rows[0].target == "http://127.0.0.1"


def test_history_list_after_scan(monkeypatch, tmp_path):
    from blacklight import history
    history.record_scan("scan", "192.168.1.10", False, {
        "hosts_scanned": 1, "services_found": 1, "findings_count": 0,
        "generated": "2026-08-04T10:00:00+00:00",
    }, [])
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "192.168.1.10" in result.output


def test_history_list_empty_exits_zero():
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "No scan history yet" in result.output


def test_history_diff_no_previous_scan_exits_zero():
    from blacklight import history
    history.record_scan("scan", "192.168.1.10", False, {
        "hosts_scanned": 1, "services_found": 1, "findings_count": 0,
        "generated": "2026-08-04T10:00:00+00:00",
    }, [])
    result = runner.invoke(app, ["history", "diff", "192.168.1.10"])
    assert result.exit_code == 0
    assert "No previous scan of 192.168.1.10" in result.output


def test_history_diff_unknown_target_exits_zero():
    result = runner.invoke(app, ["history", "diff", "10.0.0.99"])
    assert result.exit_code == 0
    assert "No scans of 10.0.0.99 yet." in result.output


def test_history_diff_bad_since_exits_one():
    result = runner.invoke(app, ["history", "diff", "10.0.0.99", "--since", "nope"])
    assert result.exit_code == 1
    assert "invalid --since value: nope" in result.output


def test_history_trend_unknown_target_exits_zero():
    result = runner.invoke(app, ["history", "trend", "10.0.0.99"])
    assert result.exit_code == 0
    assert "No scans of 10.0.0.99 yet." in result.output


def test_history_trend_bad_limit_exits_one():
    result = runner.invoke(app, ["history", "trend", "10.0.0.99", "--limit", "0"])
    assert result.exit_code == 1
    assert "LIMIT must be a positive integer" in result.output


def test_history_corrupt_db_exits_one(monkeypatch, tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not a sqlite database")
    monkeypatch.setattr("blacklight.paths.HISTORY_DB", bad)
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 1
    assert "History database error" in result.output


def test_history_help_lists_subcommands():
    result = runner.invoke(app, ["history", "--help"])
    assert result.exit_code == 0
    assert "diff" in result.output
    assert "trend" in result.output
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_cli.py -k history -v`
Expected: FAIL (no `history` command exists yet; typer raises "No such command").

- [ ] **Step 3: Wire up `blacklight/cli.py`**

Step 3a — imports. Change the top import block of `blacklight/cli.py` from:

```python
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import requests
import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from blacklight import __version__, paths
from blacklight import theme
from blacklight import enrichment, guardrails, scanner
from blacklight.cve_matcher import Finding, NvdClient, build_findings
from blacklight.reporter import export_report, render_terminal
from blacklight.web.engine import run_web_scan
```

to:

```python
import os
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import requests
import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from blacklight import __version__, history, paths
from blacklight import theme
from blacklight import enrichment, guardrails, scanner
from blacklight.cve_matcher import Finding, NvdClient, build_findings
from blacklight.reporter import export_report, render_terminal
from blacklight.web.engine import run_web_scan
```

Step 3b — record hooks. In `execute_scan`, change:

```python
    _log_scan(targets, permission_granted, result["meta"])
    render_terminal(result["findings"], result["meta"])
```

to:

```python
    _log_scan(targets, permission_granted, result["meta"])
    try:
        history.record_scan("scan", ", ".join(sorted(targets)),
                            permission_granted, result["meta"],
                            result["findings"])
    except (OSError, sqlite3.Error) as exc:
        console.print(f"[yellow]Could not record scan history:[/] {exc}")
    render_terminal(result["findings"], result["meta"])
```

In `execute_web`, change:

```python
    _log_web_scan(url, permission_granted, result.meta)
    render_terminal([], {}, web_findings=result.findings, web_meta=result.meta)
```

to:

```python
    _log_web_scan(url, permission_granted, result.meta)
    try:
        history.record_scan("web", url, permission_granted,
                            result.meta, result.findings)
    except (OSError, sqlite3.Error) as exc:
        console.print(f"[yellow]Could not record scan history:[/] {exc}")
    render_terminal([], {}, web_findings=result.findings, web_meta=result.meta)
```

Step 3c — the history sub-app and handlers. Append at the end of `blacklight/cli.py` (after the `_log_web_scan` function):

```python
history_app = typer.Typer(help="Scan history, diffs, and risk trends.")


@history_app.callback(invoke_without_command=True)
def _history_entry(ctx: typer.Context) -> None:
    """List recent scans when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        raise typer.Exit(code=_history_list())


@history_app.command()
def diff(
    target: str = typer.Argument(..., help="Target key as stored (hosts or URL)."),
    since: str | None = typer.Option(
        None, "--since",
        help="Diff against the newest scan at/before Nd or YYYY-MM-DD."),
    verbose: bool = typer.Option(
        False, "--verbose", help="List unchanged findings too."),
) -> None:
    """Show what changed between the latest scan of TARGET and its previous scan."""
    raise typer.Exit(code=_history_diff(target, since, verbose))


@history_app.command()
def trend(
    target: str = typer.Argument(..., help="Target key as stored (hosts or URL)."),
    host: str | None = typer.Option(
        None, "--host", help="Filter the trend to one host (network scans)."),
    limit: int = typer.Option(
        50, "--limit", help="Number of recent scans to include."),
) -> None:
    """Show the risk-score history for TARGET, oldest first."""
    raise typer.Exit(code=_history_trend(target, host, limit))


app.add_typer(history_app, name="history")


def _history_list() -> int:
    try:
        rows = history.list_recent()
    except sqlite3.Error as exc:
        console.print(f"[red]History database error:[/] {exc}")
        return 1
    history.render_list(rows, console)
    return 0


def _history_diff(target: str, since: str | None, verbose: bool) -> int:
    try:
        result = history.diff_for_target(target, since=since)
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        console.print("[red]Usage: history diff <target> "
                      "[--since Nd|YYYY-MM-DD] [--verbose][/]")
        return 1
    except sqlite3.Error as exc:
        console.print(f"[red]History database error:[/] {exc}")
        return 1
    if result is None:
        console.print(f"[yellow]No scans of {target} yet.[/]")
        return 0
    history.render_diff(result, console, verbose=verbose)
    return 0


def _history_trend(target: str, host: str | None, limit: int) -> int:
    if limit < 1:
        console.print("[red]LIMIT must be a positive integer.[/]")
        return 1
    try:
        points = history.trend_for_target(target, host=host, limit=limit)
    except sqlite3.Error as exc:
        console.print(f"[red]History database error:[/] {exc}")
        return 1
    if points is None:
        console.print(f"[yellow]No scans of {target} yet.[/]")
        return 0
    history.render_trend(points, console, target=target, host=host)
    return 0
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_cli.py -k history -v`
Expected: 11 passed. Then run the full suite: `python -m pytest -q`
Expected: all pass (the two new record hooks write to the conftest-isolated DB; existing scan/web tests are unaffected).

- [ ] **Step 5: Commit**

```bash
git add blacklight/cli.py tests/test_cli.py
git commit -m "feat: history CLI sub-app and scan recording hooks"
```

---

### Task 6: Console wiring (history and trend commands)

**Files:**
- Modify: `blacklight/console.py` (imports, HELP_TEXT, dispatch, two methods)
- Modify: `tests/test_console.py` (add console history tests)

**Interfaces:**
- Consumes: from Tasks 1-4 — `blacklight.history.list_recent`, `diff_for_target`, `trend_for_target`, `render_list`, `render_diff`, `render_trend`; existing `CommandRunner.execute(line, out)` dispatch structure and per-call `Console(file=out, highlight=False)`.
- Produces: console commands `history` (list), `history <target>` (diff), `trend <target>` (trend) with the same rendering as the CLI; error messages match the CLI error matrix.

- [ ] **Step 1: Write the failing tests (append to `tests/test_console.py`)**

```python
def test_console_history_lists_scans():
    from blacklight import history

    history.record_scan("scan", "192.168.1.10", False, {
        "hosts_scanned": 1, "services_found": 1, "findings_count": 0,
        "generated": "2026-08-04T10:00:00+00:00",
    }, [])
    _, out = run_commands(["history"])
    assert "192.168.1.10" in out


def test_console_history_empty_warns():
    _, out = run_commands(["history"])
    assert "No scan history yet" in out


def test_console_history_with_target_diffs():
    from blacklight import history
    from blacklight.cve_matcher import Finding

    finding = Finding(
        host="192.168.1.10", port=22, service="OpenSSH", version="9.6p1",
        cpe="cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*:*",
        cve_id="CVE-2024-0001", description="t", cvss_score=8.1,
        severity="high", fixed_version="9.7")
    meta = {"hosts_scanned": 1, "services_found": 1, "findings_count": 1,
            "generated": "2026-08-04T10:00:00+00:00"}
    history.record_scan("scan", "192.168.1.10", False, meta, [finding])
    history.record_scan("scan", "192.168.1.10", False,
                        dict(meta, generated="2026-08-04T11:00:00+00:00"), [])
    _, out = run_commands(["history 192.168.1.10"])
    assert "Risk score:" in out
    assert "improved" in out


def test_console_history_unknown_target_warns():
    _, out = run_commands(["history 10.0.0.99"])
    assert "No scans of 10.0.0.99 yet." in out


def test_console_history_usage_error():
    _, out = run_commands(["history a b"])
    assert "Usage: history [<target>]" in out


def test_console_trend_renders():
    from blacklight import history

    meta = {"hosts_scanned": 1, "services_found": 1, "findings_count": 0,
            "generated": "2026-08-04T10:00:00+00:00"}
    history.record_scan("scan", "192.168.1.10", False, meta, [])
    history.record_scan("scan", "192.168.1.10", False,
                        dict(meta, generated="2026-08-04T11:00:00+00:00"), [])
    _, out = run_commands(["trend 192.168.1.10"])
    assert "Risk trend for 192.168.1.10" in out
    assert "0.0" in out


def test_console_trend_unknown_target_warns():
    _, out = run_commands(["trend 10.0.0.99"])
    assert "No scans of 10.0.0.99 yet." in out


def test_console_trend_usage_error():
    _, out = run_commands(["trend"])
    assert "Usage: trend <target>" in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_console.py -k history -k trend -v`
Expected: FAIL (empty output — no such commands).

- [ ] **Step 3: Wire up `blacklight/console.py`**

Step 3a — imports. Change the top import block of `blacklight/console.py` from:

```python
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TextIO

from rich.console import Console

from blacklight import __version__, paths
from blacklight import theme
```

to:

```python
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TextIO

from rich.console import Console

from blacklight import __version__, history, paths
from blacklight import theme
```

Step 3b — HELP_TEXT. Change:

```python
HELP_TEXT = """Commands:
  help                 Show this help
  modules              List available modules
  use <module>         Select a module (scan, web)
  show options         Show the active module's options
  set <OPT> <value>    Set an option (e.g. set TARGET 192.168.1.10)
  unset <OPT>          Reset an option to its default
  run                  Run the active module with current options
  back                 Deselect the active module
  exit | quit          Leave the console
"""
```

to:

```python
HELP_TEXT = """Commands:
  help                 Show this help
  modules              List available modules
  use <module>         Select a module (scan, web)
  show options         Show the active module's options
  set <OPT> <value>    Set an option (e.g. set TARGET 192.168.1.10)
  unset <OPT>          Reset an option to its default
  run                  Run the active module with current options
  back                 Deselect the active module
  history              List recent scans
  history <target>     Diff the latest scan of <target> vs its previous scan
  trend <target>       Show the risk-score trend for <target>
  exit | quit          Leave the console
"""
```

Step 3c — dispatch. In `CommandRunner.execute`, change:

```python
        elif cmd == "back":
            if self.state.active is None:
                console.print("[yellow]No module selected.[/]")
            else:
                self.state.active = None
        else:
            console.print(f"[red]Unknown command: {cmd}[/] Type 'help'.")
```

to:

```python
        elif cmd == "back":
            if self.state.active is None:
                console.print("[yellow]No module selected.[/]")
            else:
                self.state.active = None
        elif cmd == "history":
            self._history(args, console)
        elif cmd == "trend":
            self._trend(args, console)
        else:
            console.print(f"[red]Unknown command: {cmd}[/] Type 'help'.")
```

Step 3d — methods. Append after `_run` (end of `CommandRunner`):

```python
    def _history(self, args: list[str], console: Console) -> None:
        if not args:
            try:
                rows = history.list_recent()
            except sqlite3.Error as exc:
                console.print(f"[red]History database error:[/] {exc}")
                return
            history.render_list(rows, console)
            return
        if len(args) != 1:
            console.print("[red]Usage: history [<target>][/]")
            return
        try:
            result = history.diff_for_target(args[0])
        except sqlite3.Error as exc:
            console.print(f"[red]History database error:[/] {exc}")
            return
        if result is None:
            console.print(f"[yellow]No scans of {args[0]} yet.[/]")
            return
        history.render_diff(result, console)

    def _trend(self, args: list[str], console: Console) -> None:
        if len(args) != 1:
            console.print("[red]Usage: trend <target>[/]")
            return
        try:
            points = history.trend_for_target(args[0])
        except sqlite3.Error as exc:
            console.print(f"[red]History database error:[/] {exc}")
            return
        if points is None:
            console.print(f"[yellow]No scans of {args[0]} yet.[/]")
            return
        history.render_trend(points, console, target=args[0])
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_console.py -v`
Expected: all pass (existing 25 + 8 new = 33). Then run the full suite: `python -m pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add blacklight/console.py tests/test_console.py
git commit -m "feat: history and trend commands in the console"
```

---

### Task 7: Version bump, console completions, full regression

**Files:**
- Modify: `pyproject.toml:7` (version)
- Modify: `blacklight/__init__.py:3` (version)
- Modify: `blacklight/console.py` (completer words)

**Interfaces:**
- Consumes: everything from Tasks 1-6.
- Produces: version 0.3.0; `history`/`trend` tab-completable in the interactive console; full test suite green.

- [ ] **Step 1: Bump the version**

In `pyproject.toml`, change `version = "0.2.0"` to `version = "0.3.0"`.

In `blacklight/__init__.py`, change `__version__ = "0.2.0"` to `__version__ = "0.3.0"`.

- [ ] **Step 2: Add console completion words**

In `blacklight/console.py`, `_run_interactive`, change:

```python
        words = [
            "help", "modules", "use", "show", "options", "set", "unset",
            "run", "back", "exit", "quit",
        ]
```

to:

```python
        words = [
            "help", "modules", "use", "show", "options", "set", "unset",
            "run", "back", "history", "trend", "exit", "quit",
        ]
```

- [ ] **Step 3: Full regression**

Run: `python -m pytest -q`
Expected: all tests pass (186 pre-existing + 37 new across `tests/test_history.py`, `tests/test_cli.py`, `tests/test_console.py`).

Run: `python -m blacklight version`
Expected: `blacklight-cli 0.3.0`

Run: `python -m blacklight --help`
Expected: help shows the `history` command group with `diff` and `trend` subcommands, and existing commands unchanged.

Run: `python -m blacklight history`
Expected: exit 0 and either the recent-scans table or `No scan history yet. Run a scan first.`

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml blacklight/__init__.py blacklight/console.py
git commit -m "feat: bump to 0.3.0, console completions for history/trend"
```

---

## Self-Review Notes (verified while writing)

- Spec coverage: storage (Task 1), network+web recording (Task 1 tests + Task 5 hooks), diff semantics + baseline rules (Task 2), `--since` (Task 2), trend scores + `--host`/`--limit` (Task 3), error matrix + exit codes (Tasks 4-6), recording-failure warning (Task 5), SQLite stdlib + no migration machinery (Task 1, `PRAGMA user_version` untouched), version 0.3.0 (Task 7). All five spec design sections have owning tasks.
- Type consistency: `DiffResult.unchanged` is a `list[FindingRecord]` everywhere (compute in Task 2, render in Task 4, tests in Tasks 2/4). `render_trend` takes `target` explicitly (Task 4) because `TrendPoint` carries no target — CLI (Task 5) and console (Task 6) both pass it. `history`/`trend` names consistent across HELP_TEXT, dispatch, and `_run_interactive` words.
- Fingerprint reconstruction for scoring uses only severity/epss/in_kev (all stored) — `Finding.version`/`cpe`/`description` and `WebFinding.url` are stubbed with safe defaults since the scoring formulas never read them.
