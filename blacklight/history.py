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