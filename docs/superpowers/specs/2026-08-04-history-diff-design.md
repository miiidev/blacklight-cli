# Scan History, Diffing & Risk Trend — Design

Date: 2026-08-04
Status: Approved (pending spec review)

## Goal

Give blacklight-cli a local, queryable scan history: every network and web scan
is persisted to `~/.blacklight/history.db` (SQLite), and users can diff a target
("what's new / what got fixed since the last scan") and trend its risk score
over time — from both the CLI and the interactive console.

Source: `docs/blacklight-cli-handoff.md` §4 "State & history" (roadmap item 2,
after the console). Accept/suppress is deliberately deferred to a follow-up.

## User decisions (from brainstorming 2026-08-04)

1. Scope: store + diffing + risk trend only. Accept/suppress (reason + expiry)
   is its own follow-up sub-project.
2. Both scan kinds (network `scan` and web `web`) are stored and diffed.
3. Persistence: SQLite via the stdlib `sqlite3` module (no new dependency),
   at `~/.blacklight/history.db`.
4. Surface: a new `history` CLI subcommand AND new console commands, sharing one
   `blacklight/history.py` library (no duplicate logic).
5. Diff baseline: the immediately-previous scan of the same target by default,
   with an optional `--since <Nd|YYYY-MM-DD>` to compare against an older scan.
6. Trend scores are computed at query time from stored findings (never stored,
   so they cannot go stale).
7. Version bump to `0.3.0` with this feature (repo convention since 0.2.0).

## Architecture

### Files

| File | Change | Responsibility |
|---|---|---|
| `blacklight/history.py` | **new** | `record_scan`, queries, diff, trend (pure, sqlite3) |
| `blacklight/paths.py` | modified | add `HISTORY_DB = HOME_DIR / "history.db"` |
| `blacklight/cli.py` | modified | persist in `execute_scan`/`execute_web`; `history` subcommand |
| `blacklight/console.py` | modified | `history`, `history <target>`, `trend <target>` commands |
| `pyproject.toml`, `blacklight/__init__.py` | modified | version `0.3.0` |
| `tests/test_history.py` | **new** | store, diff, trend unit + CLI integration tests |
| `tests/test_cli.py`, `tests/test_console.py` | modified | persistence hooks + console dispatch tests |
| everything else | untouched | scanner, cve_matcher, enrichment, scoring, guardrails, reporter, theme, web engine |

### Store schema (`~/.blacklight/history.db`)

Created on demand with `CREATE TABLE IF NOT EXISTS`:

```sql
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT NOT NULL,          -- 'scan' | 'web'
    target         TEXT NOT NULL,          -- canonical target key
    permission     INTEGER NOT NULL,       -- 0/1
    scanned_at     TEXT NOT NULL,          -- ISO UTC, meta['generated']
    hosts          INTEGER NOT NULL DEFAULT 0,
    services       INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    kind        TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    host        TEXT,                      -- network: host; web: NULL
    port        INTEGER,                   -- network only
    service     TEXT,                      -- network only
    cve_id      TEXT,                      -- network: CVE id; web: optional
    category    TEXT,                      -- web: check category
    detail      TEXT,                      -- network: description; web: finding detail
    evidence    TEXT,                      -- web only
    severity    TEXT NOT NULL,
    cvss        REAL,
    epss        REAL,
    in_kev      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scans_kind_target ON scans(kind, target, scanned_at);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
```

No migration machinery in this sub-project (`PRAGMA user_version` reserved for
future sub-projects).

### Capture (in `blacklight/cli.py`)

Inside `execute_scan` and `execute_web`, immediately after the existing
`_log_scan` / `_log_web_scan` call, invoke `history.record_scan(...)`:

- network: `record_scan("scan", target_key, permission_granted, meta, findings)`
  where `target_key = ", ".join(sorted(targets))` (order-insensitive identity),
  `findings` = `result["findings"]` (list of `Finding`).
- web: `record_scan("web", url, permission_granted, meta, findings)` where
  `url` is the normalized URL already computed in `execute_web`, `findings` =
  `result.findings` (list of `WebFinding`).

`record_scan` inserts the scan row, then one finding row per finding. The whole
call is wrapped in try/except (`sqlite3.Error`, `OSError`) — on failure print
`[yellow]Warning: could not record scan in history: {exc}[/]` and continue; a
history failure must never fail a completed scan. The call site in `cli.py`
carries the try/except (same pattern as the export block).

`hosts`/`services`/`findings_count` come from `meta` for network scans
(`hosts_scanned`, `services_found`, `findings_count`); web scans use 0 for
hosts/services and `findings_count = len(findings)` (web meta has no
`findings_count` key — only `cve_findings`).

### Fingerprints

| Kind | Fingerprint (pipe-joined) | Rationale |
|---|---|---|
| network | `host \| port \| service \| cve_id` (when `cve_id` empty: `v:<version>`) | CVE-level identity; falls back to service+version |
| web | `url \| category \| detail` | checks share categories; detail distinguishes findings |

Fingerprints are computed inside `record_scan` and stored on the finding row.

### Diff

Query the two scans of the same `kind` + `target` key:

- Baseline: the scan with the largest `id` strictly before the selected scan's
  `id` (default: the selected scan is the latest overall).
- With `--since <value>`: the selected scan is still the latest; the baseline
  is the newest scan with `scanned_at <= cutoff`. `--since` accepts `Nd` (N
  days, computed from today) or `YYYY-MM-DD`. Parse failures print
  `[red]Invalid --since value: {value}. Use N days (7d) or YYYY-MM-DD.[/]` and
  exit 1.

Buckets (set difference on fingerprints):
- **NEW** — in the selected scan, not in the baseline.
- **FIXED** — in the baseline, not in the selected scan.
- **UNCHANGED** — in both. Shown as a single count line unless `--verbose`
  (then listed like NEW/FIXED).

Each bucket row shows: network → `host:port service — cve_id (severity)` and
description as secondary text; web → `category: detail (severity)`, evidence as
secondary text.

**Score delta:** latest scan's risk score minus the baseline's. Network score =
max `host_risk_score` across the scan's hosts; web score = `web_risk_score`.
Rendered as `X.X → Y.Y ▲ worsened` / `▼ improved` / `— unchanged` (delta > 0.05
worsened, < -0.05 improved, else unchanged).

Edge cases:
- No previous scan of that target: `[yellow]No previous scan of {target}.[/]`
  exit 0.
- `--since` selects a cutoff before any scan: same "No previous scan" message.
- Only one scan exists for the target: same message.

### Trend

Query all scans of `kind` + `target` key, newest last. Table columns:
`scanned_at | kind | risk score | findings count`.

- Score per row computed at query time: network → max `host_risk_score` across
  hosts (or a single host's score when `--host <ip>` is given, filtering to
  findings of that host); web → `web_risk_score`.
- Score cells render with the existing `theme.risk_gauge` bars + the number.
- `--limit N` (default 50) keeps the newest N scans.
- Empty history for the target: `[yellow]No scans of {target} yet.[/]` exit 0.

### Surfacing

CLI — new nested `history` subcommand (visible in `blacklight --help`):

```
blacklight history                       → recent scans table (id, kind, target,
                                          scanned_at, findings_count), newest first,
                                          capped at 20 rows
blacklight history diff <target>         → diff buckets + score delta
                                          (--since 7d | --since 2026-07-01, --verbose)
blacklight history trend <target>        → score series table
                                          (--host <ip>, --limit N)
```

Exit codes: 0 for success and for the no-history/no-previous-scan messages; 1
for corrupt/unreadable DB (`[red]History database is unreadable: {exc}[/]`) and
usage errors (bad `--since`).

No history at all (empty DB or no DB): `[yellow]No scan history yet. Run a scan first.[/]` exit 0.

Console — three commands, same library:

```
blacklight > history              → recent scans list (same table as CLI)
blacklight > history 192.168.1.10 → diff for that target
blacklight > trend 192.168.1.10   → trend table
```

Console behavior: errors print `[red]`/`[yellow]` lines and the loop continues;
unknown/empty-target forms print a usage hint.

## Error handling matrix

| Case | Behavior |
|---|---|
| DB write fails during scan | yellow warning; scan completes normally |
| No history DB/table on read | "No scan history yet. Run a scan first." exit 0 |
| Corrupt DB on read | `[red]History database is unreadable: {exc}[/]` exit 1 |
| Bad `--since` value | red usage error, exit 1 |
| No previous scan of target | yellow "No previous scan of {target}." exit 0 |
| No scans of target for trend | yellow "No scans of {target} yet." exit 0 |
| Console: bad command form | red usage hint, loop continues |

## Testing

- `tests/test_history.py`:
  - `record_scan` writes a scan row + finding rows (tmp_path `HISTORY_DB`); counts from meta.
  - Fingerprints: network with/without `cve_id`; web with shared category, distinct detail.
  - Diff: NEW/FIXED/UNCHANGED across two fabricated scans (network + web); `--since` baseline selection (Nd and date); "no previous scan" cases; score delta buckets (worsened/improved/unchanged).
  - Trend: series order, per-host `--host` filter, `--limit`, risk-gauge presence.
  - CLI integration via CliRunner: `history`, `history diff <target>`, `history trend <target>` (monkeypatched `paths.HISTORY_DB`); exit codes for empty/corrupt DB; corrupt DB via a non-SQLite file.
- `tests/test_cli.py`:
  - A successful `execute_scan` writes history rows; a failed scan writes none; a DB-write failure still returns the scan's success code and prints the warning.
  - Same for `execute_web`.
- `tests/test_console.py`:
  - `history` (list), `history <target>` (diff), `trend <target>` (trend) dispatch with a stubbed history library or tmp DB; unknown-target message; loop continues.
- Full existing suite stays green (186 tests); manual smoke: run a scan twice, `blacklight history diff <target>` shows NEW/FIXED, `blacklight history trend <target>` shows the series.

## Dependencies & packaging

- No new dependency (stdlib `sqlite3`).
- Version `0.3.0` in `pyproject.toml` and `blacklight/__init__.py::__version__`
  (the version test already uses `__version__`, no test change needed).
- `blacklight/history.py` imports only stdlib + `blacklight` leaf modules
  (`paths`, `scoring`, `theme`) — never `cli` or `console`.

## Out of scope

- Accept/suppress with reason + expiry (follow-up; schema supports it).
- Replacing or migrating `scan.log`.
- History retention/pruning policies.
- Networked/remote history storage.
- Diffing service-level changes (only findings diff; hosts/services counts are
  context lines).
