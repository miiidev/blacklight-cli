# blacklight-cli — Network Vulnerability Scanner: Design Spec

**Date:** 2026-07-31
**Status:** Approved
**Package name:** `blacklight-cli` (command: `blacklight`) — verified available on PyPI; `vulnscan` and `blacklight` are taken.
**Python:** 3.11+
**Goal:** A local, deterministic (no LLM/API AI) CLI tool that scans hosts/networks for open ports and service versions, cross-references them against the NVD CVE database with EPSS/KEV enrichment, and produces a severity-ranked, exploitation-prioritized report with rich terminal output.

## Purpose

- Runs entirely locally; no hosting cost for core functionality.
- Polished CLI experience via `rich`.
- Packaged and distributable via PyPI.
- Standout features over commodity nmap+NVD wrappers: EPSS/KEV overlay (patch-priority, not just CVSS) and per-host risk scores.

## Architecture

```
target(s)/CIDR
      │
      ▼
scanner.py        ── `nmap -sV -oX -` via subprocess, XML parsed with stdlib ElementTree
      │               → {host, port, protocol, service, version}
      ▼
cpe_map.py        ── service name → CPE vendor:product mapping (~50-100 common services)
      ▼
cve_matcher.py    ── NVD lookup per CPE (cached, rate-limited) → findings with CVSS
      ▼
enrichment.py     ── EPSS odds (batch, keyless) + KEV "actively exploited" badge
      ▼
scoring.py        ── 0-100 host risk score per host
      ▼
reporter.py       ── rich terminal output + HTML/Markdown/JSON export
```

## Project Layout

```
blacklight/
├── pyproject.toml          # PyPI: blacklight-cli, command: `blacklight`, Python 3.11+
├── README.md
├── blacklight/
│   ├── __init__.py
│   ├── cli.py              # typer entry point
│   ├── scanner.py          # nmap subprocess + XML parsing
│   ├── cpe_map.py          # service → CPE mapping table
│   ├── cve_matcher.py      # NVD lookups + local cache + rate limiting
│   ├── enrichment.py       # EPSS + KEV overlay
│   ├── scoring.py          # host risk score formula
│   ├── guardrails.py       # IP checks, permission flag, scan log
│   ├── reporter.py         # rich terminal output + Jinja2 export
│   └── templates/          # HTML/Markdown templates
├── tests/
└── examples/
```

Dependencies: `typer`, `rich`, `jinja2`, `requests`. No `python-nmap` (shell out + parse XML directly).

Local state in `~/.blacklight/`: `cache/` (CPE + EPSS lookup cache, daily KEV feed), `scan.log`.

## Components

### 1. Scanner (scanner.py)

- Shells out to `nmap -sV -oX -` via subprocess; parses XML with stdlib `xml.etree.ElementTree`.
- Runtime nmap detection: if `nmap` not on PATH, print per-OS install hints (`apt install nmap`, `brew install nmap`, `choco install nmap`) and exit cleanly.
- Output: structured `{host, port, protocol, service, version}` records.

### 2. CPE Mapping (cpe_map.py)

- Curated table mapping nmap service names → CPE vendor:product (~50-100 common services: openssh → openbsd:openssh, apache httpd → apache:http_server, nginx → f5:nginx, mysql → mysql:mysql, etc.).
- Parses nmap version strings: `OpenSSH 9.6p1 Ubuntu 3ubuntu13.5` → product `openssh`, version `9.6` (strip OS suffix/patch levels). Handle versionless services.

### 3. CVE Matcher (cve_matcher.py)

- Per unique `product:version` (deduped — a /24 scan typically needs only a handful of lookups):
  - Query NVD `GET /rest/json/cves/2.0?cpeName=cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*`
  - No CPE match → fallback to NVD keyword search (`keywordSearch=openssh 9.6`).
- Optional free NVD API key via `BLACKLIGHT_NVD_KEY` env var: 50 req/30s; without key, auto-throttle to 5 req/30s.
- Cache lookups in `~/.blacklight/cache/` keyed by `product:version`, TTL 7 days; `--no-cache` flag bypasses.
- Finding shape: `{host, port, service, version, cpe, cve_id, description, cvss_score, severity, fixed_version?, epss, in_kev}`.

### 4. Enrichment (enrichment.py)

- EPSS: batch query `https://api.first.org/data/v1/epss?cve=ID1,ID2,...` (keyless, up to 100 CVEs per request) → exploitation probability 0–1, cached.
- KEV: CISA known-exploited list (keyless JSON feed, ~1.5MB) downloaded at first use, refreshed daily; badge findings whose CVE is in the list.

### 5. Risk Score (scoring.py)

- Per host, 0–100, transparent and documented:
  - Base = sum of severity weights (critical=20, high=10, medium=4, low=1), capped.
  - +10 per KEV finding (capped).
  - +up to 10 scaled by max EPSS among the host's findings.
  - Overall cap 100. Formula documented in README and shown in report footer.

### 6. Guardrails (guardrails.py)

- Default-deny: only RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and loopback (`127.0.0.0/8`) scannable by default.
- Any public IP/CIDR in `--target` blocks unless `--i-have-permission` passed.
- With the flag + public target: still show a warning and require interactive `y` confirmation.
- Check applies per-IP after CIDR expansion (no public IPs sneaking through a mixed range).
- Every scan appended to `~/.blacklight/scan.log`: timestamp, target, permission flag, duration, hosts scanned.
- README + `blacklight --help` carry the "only systems you own or are authorized to test" statement.

### 7. Reporter (reporter.py)

- Terminal (rich): progress bars per phase (scanning → CVE matching → enrichment); severity-colored findings table (critical=red, high=orange, medium=yellow, low=default) with EPSS % and KEV badge columns; summary panel (hosts, services, findings by severity, host risk score table).
- Export: HTML (Jinja2), Markdown, JSON (raw structured data for scripting).

### 8. CLI (cli.py)

```
blacklight scan 192.168.1.0/24 [--ports 1-1024] [--output report.html]
                   [--format markdown|html|json] [--i-have-permission]
                   [--no-cache] [--timeout 30]
```

## Installation & Dependencies

- Dependencies declared in `pyproject.toml`; installed automatically by `pip install blacklight-cli`, `pipx install`, or `uv tool install` (isolated env; recommended paths).
- The nmap binary is the only manual system dependency — documented in README, detected at runtime with per-OS install hints.

## Testing

- `pytest`; no live network scans in CI.
- scanner: fixture nmap XML files (real `-sV` output samples) → parse assertions.
- cve_matcher: mocked NVD API responses; cache hit/miss; rate-limit behavior.
- enrichment: mocked EPSS/KEV payloads; KEV daily-refresh logic.
- scoring: formula unit tests (weights, KEV bonus, EPSS scaling, caps).
- guardrails: public/private IP matrix, CIDR edge cases, flag-required paths.
- cpe_map: version-string parsing edge cases (`9.6p1 Ubuntu`, versionless).
- Manual: scan a local Metasploitable VM or localhost.

## Milestones

1. MVP scan engine — nmap wrapper + XML parse, print raw findings
2. Guardrails — default-deny, permission flag, scan log
3. CVE matching — CPE map + NVD lookups + cache
4. Enrichment — EPSS + KEV overlay
5. Risk scoring — host risk scores
6. Rich terminal output — progress, severity table, summary panel
7. File export — HTML/Markdown/JSON
8. Packaging — pyproject.toml, local install, publish to PyPI
9. Polish — README, usage docs, Metasploitable demo
10. Stretch — PDF export, textual TUI, Docker image

## Resolved Decisions (from prior session + this session)

- Flavor: network/host vuln scanning; local CLI; terminal-first via rich.
- CVE source: **NVD API via CPE lookup** (free key: 50 req/30s; keyless: 5 req/30s).
- Scan engine: **subprocess + XML parse** (no python-nmap).
- Package name: **blacklight-cli** (blacklight taken).
- Python: **3.11+**.
- Install: **pip/pipx/uv + runtime nmap check**.
- Standout features: **EPSS + KEV overlay, host risk score** (diffing, EOL detection, coverage gaps, offline mode considered and declined for MVP).
