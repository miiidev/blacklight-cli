"""Scan history persistence: SQLite storage of network and web scan findings."""

import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from blacklight import paths
from blacklight.cve_matcher import Finding
from blacklight.scoring import host_risk_score, web_risk_score
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