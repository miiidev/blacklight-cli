# blacklight-cli — Web Application Scanning: Design Spec

**Date:** 2026-08-01
**Status:** Approved
**Package name:** `blacklight-cli` (command: `blacklight`)
**Python:** 3.11+
**Goal:** Extend blacklight-cli with a `web` subcommand that passively probes web applications (security headers, exposed files/misconfigs, error-based SQLi/XSS/command-injection on GET parameters) and fingerprints tech versions into the existing CPE → NVD CVE pipeline. Deterministic, local, no new dependencies, no exploitation.

## Purpose

- Close the gap surfaced by the bWAPP test: the network scanner only detects service-version CVEs; web application bugs (SQLi, XSS, misconfigs) are invisible to it.
- Keep the project's design philosophy: local, deterministic (no LLM), error-based detection only (no blind/time-based techniques, no exploitation), polished rich output, PyPI-distributable.
- Reuse the existing pipeline (guardrails, NVD client + cache, EPSS/KEV, reporter, scan log) instead of parallel infrastructure.

## Scope

**In scope (v1):**
- `blacklight web <url>` subcommand with URL-based guardrails (hostname resolution — fixes the "hostnames always blocked" limitation of `scan`).
- ~20 built-in checks across 5 categories: security headers, exposed files & misconfigs, SQLi on GET params, XSS / command injection on GET params, tech fingerprint → CVE.
- Error-based detection only: crafted payloads + response analysis (error strings, status/behavior changes). No timing, no blind, no out-of-band, no exploitation.
- Web findings rendered in terminal, HTML, Markdown, JSON; logged to `~/.blacklight/scan.log`.

**Out of scope (v1):**
- POST form probing (form parsing, CSRF tokens, session handling).
- Recursive crawling: homepage links are used only as probe targets (param fuzzing, path checks), never followed into further pages; no JS execution.
- Blind/time-based/out-of-band techniques; actual exploitation.
- Authenticated scans (no session/login support).
- nikto or other external scanners (all checks built-in, Python only).

## Architecture

```
blacklight web https://target
      │
      ▼
guardrails (web)      ── URL parse → hostname resolve → is_private (RFC1918 + loopback)
      │                  public → --i-have-permission + interactive confirm
      ▼
web/engine.py         ── fetch homepage + headers (requests, 30s timeout)
      │                  run each check in the registry (isolated, failure-tolerant)
      ▼
web/checks.py         ── security headers │ exposed files & misconfigs │
                        SQLi │ XSS │ command injection     → WebFinding[]
      │
      ▼
web/fingerprint.py    ── server header / framework markers → version
      │                  → cpe_map.service_to_cpe() → NvdClient.build_findings()
      │                  → enrichment.enrich_findings()  (existing EPSS/KEV path)
      ▼
scoring.py            ── web risk score (severity-weighted base only; EPSS/KEV 0)
      ▼
reporter.py           ── web section in terminal + HTML/Markdown/JSON export
      ▼
_log_scan             ── ~/.blacklight/scan.log (URL, permission, checks, findings)
```

## Project Layout (additions)

```
blacklight/
├── web/
│   ├── __init__.py        # public API: run_web_scan()
│   ├── models.py          # WebFinding dataclass
│   ├── http.py            # thin requests wrapper (fetch, GET with params) — single mock point for tests
│   ├── checks.py          # check registry + individual checks (~20)
│   ├── fingerprint.py     # server/framework/version detection → CPE
│   └── engine.py          # orchestrates checks + fingerprint, collects results
└── cli.py                 # adds `web` subcommand
tests/
├── test_web_checks.py
├── test_web_engine.py
├── test_web_fingerprint.py
├── test_web_guardrails.py
└── test_cli_web.py
```

No new dependencies: `requests`, `typer`, `rich`, `jinja2`, plus stdlib (`urllib.parse`, `socket`, `re`).

## Components

### 1. Data Model (web/models.py)

`WebFinding` dataclass:

| field | type | meaning |
|---|---|---|
| `url` | str | URL the check ran against |
| `category` | str | check category (e.g. `security_header`, `exposed_file`, `sqli`, `xss`, `cmd_injection`, `fingerprint`) |
| `detail` | str | human-readable finding description |
| `severity` | str | fixed per check: `critical`/`high`/`medium`/`low`/`unknown` |
| `evidence` | str | response snippet/header that triggered the finding (truncated ~200 chars) |
| `cve_id` | str | empty unless a fingerprint match produced a CVE |
| `epss` | float \| None | None unless CVE-backed (enrichment fills it) |
| `in_kev` | bool | False unless CVE-backed |

Methods: `to_dict()` for JSON export. Existing `Finding` untouched.

### 2. HTTP wrapper (web/http.py)

- `fetch_page(url, timeout=30) -> Page` — GET with browser-ish headers; `Page` holds `status, headers (case-insensitive dict), text (decoded), final_url`.
- `probe(url, params, timeout=30) -> ProbeResult` — GET with crafted params; returns status + text snippet.
- All network I/O goes through this module so tests monkeypatch one place. Errors raised: `requests.RequestException` subclasses, converted by the engine into a graceful failure.

### 3. Check Registry (web/checks.py)

Each check is a function `check(page, http) -> WebFinding | None` registered in a module-level `CHECKS` list. The engine runs every check independently; a raising check is caught, counted in meta `checks_errored`, and never aborts the run.

**Security headers** (all `low`, on every response): `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security` (https only), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.

**Exposed files & misconfigs** (probe list; `high` unless noted):
- `/.git/` (directory listing or `HEAD` 200), `/.env`, `/phpinfo.php` (page contains `phpinfo()` marker), `/server-status` (Apache marker), `/admin`, `/login` (200 + form/link marker), `/wp-admin` (WordPress marker) — `medium`
- backup files: `/.git/config`, `/*.bak` for any discovered `.php` path, `/.DS_Store`
- directory listing enabled (response contains `Index of /` marker) — `medium`
- default page marker (default Apache/nginx/IIS install pages) — `medium`

**SQLi on GET params** (`high`): for each `<a href>` link on the homepage with query params (same-origin only, max 10 params, deduped):
1. Baseline: GET the URL as-is.
2. Payload 1: replace one param value with `'` (single quote).
3. Payload 2: replace with `' OR 1=1 -- ` (URL-encoded).
4. Triggered if payload response contains SQL error signatures (regex list: `SQL syntax|mysql_fetch|ORA-[0-9]{5}|PostgreSQL.*ERROR|Unclosed quotation mark|Microsoft OLE DB|SQLSTATE`) and the baseline does not.

**XSS / command injection on GET params** (`medium` / `high`):
- XSS: one payload `"><svg/onload=alert(1)>`; reflected if the raw payload appears in the response body (and not in the baseline).
- Command injection: payload `;id` plus `& ping -c 1 127.0.0.1 &` (encoded); triggered on shell error/behavior signatures (`sh:`, `command not found`, `uid=`, `/bin/sh`).

All payloads error-based only, response-analysis only, max 10 params per page, single homepage crawl.

### 4. Fingerprint → CVE (web/fingerprint.py)

- Extract `Server` header (e.g. `Apache/2.4.49 (Ubuntu)`), `X-Powered-By` (`PHP/7.4.33`), `Set-Cookie` hints (phpMyAdmin/WordPress), HTML markers (generator meta, `/wp-content/`, `/phpmyadmin/`).
- Produce `Fingerprint(service, version)` structs → reuse `cpe_map.extract_version` + `service_to_cpe` (extend table with `apache` variants, `php`, `wordpress`, `phpmyadmin` as needed — already present for common ones).
- CPE match → existing `NvdClient.lookup` (cached, rate-limited, `--no-cache` honored) → `build_findings` → EPSS/KEV enrichment. CVE-backed findings get `cve_id`/`epss`/`in_kev`; non-CVE web findings don't.

### 5. Engine (web/engine.py)

`run_web_scan(url, timeout=30, no_cache=False) -> WebResult` with `WebResult(findings: list[WebFinding], meta: dict)`:
- meta keys: `url, host, resolved_ip, checks_run, checks_errored, generated, cve_findings` (count of CVE-backed).
- fetch homepage; run all checks; run fingerprint → CVE pipeline; catch per-check errors; count and continue.

### 6. CLI (cli.py)

```
blacklight web <url> [--i-have-permission] [--no-cache] [--output/-o] [--format html|markdown|json] [--timeout]
```

- URL normalization: bare hostnames get `https://`; reject non-http(s) schemes and unparseable URLs (exit 1, message).
- Guardrails: resolve hostname via `socket.getaddrinfo` (monkeypatchable); `guardrails.is_private(ip)`; public → `--i-have-permission` required + `typer.confirm`; decline → `Aborted.` exit 1; resolution failure → blocked with message.
- nmap not required for `web` (no dependency on the nmap binary).
- Same graceful-degradation pattern: wrap `run_web_scan` in try/except → `Web scan failed: <reason>` + exit 1, no traceback.
- `_log_scan` gains a `web` variant line: `generated url=... ip=... permission=... checks=... findings=...`.

### 7. Scoring (scoring.py)

- `host_risk_score` hardened: `epss=None` treated as `0.0` (add test) — behavior for existing findings unchanged.
- Web risk score = same severity-weight formula with EPSS/KEV terms zeroed (they are None/False for non-CVE web findings). Deliberate conservative choice (amended at implementation): CVE-backed fingerprint findings also score severity-only — EPSS/KEV enrich their report rows but do not add to the web score, which understates rather than overstates risk.

### 8. Reporter (reporter.py + templates)

- Terminal: web findings table `Category | URL | Severity | Detail | Evidence` (severity-styled like the existing table); CVE-backed rows show CVE ID/EPSS/KEV columns too. Summary panel gains `Web checks run` / `Web findings`.
- HTML/Markdown templates: web findings section (same structure as the findings table); JSON: `findings` list of `to_dict()` objects with a `type: "web"` marker plus the existing `type: "cve"` for network findings.

## Error Handling

| failure | behavior |
|---|---|
| invalid URL / non-http scheme | usage error, exit 1 |
| hostname unresolvable | blocked message, exit 1 |
| public target without permission | blocked message, exit 1 |
| public target, confirm declined | `Aborted.`, exit 1 |
| connection/TLS/timeout/HTTP 5xx | `Web scan failed: <reason>`, exit 1, no log line |
| individual check raises | caught, counted in `checks_errored`, run continues |
| NVD/EPSS/KEV failure during fingerprint CVE lookup | `Web scan failed: <reason>` (existing graceful-degradation envelope) |

## Testing (all network-free)

- `test_web_checks.py`: one test per check with monkeypatched `web.http` (fake Page/ProbeResult); SQLi/XSS/injection tables: payload → signatures triggered / not triggered; per-check isolation (a raising check doesn't stop the engine).
- `test_web_engine.py`: end-to-end with faked http + fake NvdClient; meta keys; checks_errored counting; CVE-backed vs non-CVE findings.
- `test_web_fingerprint.py`: `Server: Apache/2.4.49` → `apache:http_server`, version extraction edge cases (no version, weird casing); WordPress/phpMyAdmin markers.
- `test_web_guardrails.py` + `test_cli_web.py`: CliRunner flows — blocked public, confirm declined, end-to-end private URL with faked socket resolution and http, missing-flag behavior, `--output` export with web findings.
- `test_scoring.py`: new test `epss=None` → weight 0.
- Full suite must stay green (68 existing + new).

## Verification

- `python -m pytest -q` green.
- Manual smoke: `blacklight web http://127.0.0.1` against a local test server the user authorizes; public site requires `--i-have-permission`.
- README updated: `web` command section, check categories, ethics note stays.
